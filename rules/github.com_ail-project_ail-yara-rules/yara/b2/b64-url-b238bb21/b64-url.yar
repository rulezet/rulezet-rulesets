rule b64_url
{
    meta:
        author = "@KevTheHermit"
        info = "Part of PasteHunter"
        reference = "https://github.com/kevthehermit/PasteHunter"

    strings:
        $a1 = "aHR0cDov"         $a2 = "SFRUUDov"         $a3 = "d3d3Lg"         $a4 = "V1dXLg" 
                $not1 = "GlobalSign Root CA" nocase

                $not2 = /data:[a-z0-9\/]+;(base64,)?aHR0cDov/ nocase
        $not3 = /data:[a-z0-9\/]+;(base64,)?SFRUUDov/ nocase
        $not4 = /data:[a-z0-9\/]+;(base64,)?d3d3Lg/ nocase
        $not5 = /data:[a-z0-9\/]+;(base64,)?V1dXLg/ nocase

    condition:
        any of ($a*) and not any of ($not*)

}