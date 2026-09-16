rule locky_panel__botgeneration : malware
{
    meta:
        description = "Identify locky/ransomware builder"
        author = "@h3x2b <tracker _AT h3x.eu>"
                
    strings:
        $s01 = "make_bot_exe"
        $s02 = "BOT_EXES_PATH"
        $s03 = "Locky_{*}.exe"
        $s04 = "Location:"
        $s05 = "BOT_EXES_URL"

    condition:
        all of them

}