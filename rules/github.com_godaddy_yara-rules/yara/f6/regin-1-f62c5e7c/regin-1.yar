rule Regin_1 {
    meta:
        info = "Regin"

    strings:
            $string_decode = {55 8b ec 5d 8b 45 08 0b c0 74 0c eb 05 fe 08 fe 08 40 80 38 00 75 f6}

    condition:
            $string_decode
}