rule granite_jocasteluvium {
    strings:
        $mz = "MZ"

                $string1 = "JumpID(\"\",\"%s\")"
        $string2 = " - Clipboard - "
        $string3 = "Content-Type: application/x-www-form-urlencoded"
        $string4 = "text="
        $string5 = "[Num Lock]"
        $string6 = "[PrtScr]"
        $string7 = "msgss.exe"
        $string8 = "User Interface Manager" wide

    condition:
        $mz at 0 and 7 of ($string*)
}