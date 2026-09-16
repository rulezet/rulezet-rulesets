rule appraisel_exe_payload {
    meta:
        decoder = "appraisel_exe_payload.py"

    strings:
        $filename1 = "%s\\Tmp" wide
        $filename2 = "%s\\Volume Panel" wide
        $filename3 = "\\VolPanlu.exe" wide
        $filename4 = "%s\\updstat.bin" wide
        $filename5 = "%s\\srvstat.bin" wide

        $string1 = "Panlu" wide fullword

                $3min_uptime_test = {FF15????????3D20BF0200730B68C0D40100FF15????????680F270000}

    condition:
        4 of ($filename*,$string1) or $3min_uptime_test
}