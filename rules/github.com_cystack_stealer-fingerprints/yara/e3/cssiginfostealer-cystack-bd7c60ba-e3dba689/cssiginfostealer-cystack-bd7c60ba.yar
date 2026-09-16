rule CSSigInfoStealer_cystack_bd7c60ba
{
    meta:
        family = "CSSigInfoStealer"
        fingerprint_id = "cystack_bd7c60ba"

    strings:
        $key_0 = "Book:" ascii
        $key_1 = "Country:" ascii
        $key_2 = "Date:" ascii
        $key_3 = "IP Address:" ascii
        $key_4 = "Language:" ascii
        $key_5 = "Location:" ascii
        $key_6 = "Lyrics:" ascii
        $key_7 = "Music:" ascii
        $key_8 = "Performers:" ascii
        $key_9 = "Show:" ascii
        $key_10 = "Time:" ascii
        $key_11 = "Tracks:" ascii
        $key_12 = "Translation:" ascii
        $key_13 = "User:" ascii

    condition:
        all of ($key_*)
}