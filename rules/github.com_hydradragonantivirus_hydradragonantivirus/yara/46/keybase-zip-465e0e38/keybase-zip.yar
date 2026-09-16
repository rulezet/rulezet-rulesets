rule keybase_zip

{

    meta:
        description = "Find zip archives of panels"
        author = "Brian Carter"
        last_modified = "March 31, 2017"
        
    strings:
        $txt1 = "clipboard.php"
        $txt2 = "config.php"
        $txt3 = "create.php"
        $txt4 = "login.php"
        $txt5 = "screenshots.php"
        $magic = { 50 4b 03 04 }
        
    condition:
        $magic at 0 and all of ($txt*)
        
}