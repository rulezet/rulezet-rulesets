rule function_drop {
    meta:
        description = "Chinese Hacktool Set - file function_drop.php"
        author = "Florian Roth"
        reference = "http://tools.zjqhr.com/"
        date = "2015-06-13"
        hash = "209098c494ce10d82d1c2002488509c5e8983182"
    strings:
        $s0 = "@mssql_query('DROP FUNCTION ' . urldecode($_GET['function']) . ';') or" ascii
        $s1 = "$_GET['returnto'] = 'database_properties.php';" fullword ascii
        $s2 = "echo('<meta http-equiv=\"refresh\" content=\"0;url=' . $_GET['returnto'] . '\">'" ascii
        $s3 = "if(empty($_GET['returnto']))" fullword ascii
    condition:
        filesize < 5KB and all of them
}