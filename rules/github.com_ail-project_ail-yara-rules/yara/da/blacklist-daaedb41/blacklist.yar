rule blacklist
{
    meta:
        author = "@KevTheHermit"
        info = "Part of PasteHunter"
        reference = "https://github.com/kevthehermit/PasteHunter"

    strings:
        $a = "#EXTINF:" nocase         $b = "--app-name=LeagueClient" nocase         $c = "common.application_name: LeagueClient"         $d = /java\.(util|lang|io)/         $e = "Traceback (most recent call last)"
        $f = /define\(.*?\)|require_once\(.*?\)/
        $g = "Technic Launcher is starting"         $h = "OTL logfile created on"     condition:
        any of them
}