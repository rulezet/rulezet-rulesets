rule database_export {
    meta:
        description = "Chinese Hacktool Set - file database_export.php"
        author = "Florian Roth"
        reference = "http://tools.zjqhr.com/"
        date = "2015-06-13"
        hash = "edcf8ef761e7e09a6a4929ccbc2aa04c7011ae53"
    strings:
        $s0 = "header('Content-Length: ' . strlen($masterquery));" fullword ascii
        $s3 = "echo '<form name=\"form1\" method=\"post\" action=\"database_export_download.php" ascii
        $s7 = "if(substr_count($_POST['tables'][$counter],'.') > 0)" fullword ascii
        $s19 = "<input type=\"hidden\" name=\"doexport\" value=\"yes\">" fullword ascii
    condition:
        filesize < 100KB and all of them
}