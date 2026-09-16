rule INDICATOR_KB_GoBuildID_Snatch {
    meta:
        author = "ditekSHen"
        description = "Detects Golang Build IDs in known bad samples"       
    strings:
        $s1 = "Go build ID: \"8C2VvDTH-MuUPx8tL42E/PWF9iuE2j_Zt0ANsTlty/c64swZ5TtuaIpHuEFmga/6sS0KWNryc-YAduDnWWO\"" ascii
        $s2 = "Go build ID: \"UBrfJ_wztDfCHWakqvlV/LhzfkJwvKFrNhKCHtU9_/sveCupt8GVbvu6WZiyA-/GcimfL_TPl6FTPPriBDr\"" ascii
        $s3 = "Go build ID: \"5zCy9jt7UZaIs5YPk4tt/1Yt6v7gCpDG---pRFyW-/7729nLSeKJik31ftz_Ve/Z5EVG3lWak3ynxNrJ4ih\"" ascii
    condition:
        uint16(0) == 0x5a4d and 1 of them
}