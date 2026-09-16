rule new_pony_panel

{

    meta:
        description = "New Pony Zips"
        
    strings:
        $txt1 = "includes/design/images/"
        $txt2 = "includes/design/style.css"
        $txt3 = "admin.php"
        $txt4 = "includes/design/images/user.png"
        $txt5 = "includes/design/images/main_bg.gif"
        $magic = { 50 4b 03 04 }
        
    condition:
        $magic at 0 and all of ($txt*)
        
}