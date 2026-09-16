rule wiper_payload_dropper2 {
    meta:
        description = "Wiper implant"
        filename = "ams.exe"

    strings:
        $MZ = "MZ"

                $process_hacker_ascii = {5c4465766963655c4b50726f636573734861636b657232}
        $process_hacker_unicode = {5c004400650076006900630065005c004b00500072006f0063006500730073004800610063006b006500720032000000}
        $mcshield_string = {53595354454d5c43757272656e74436f6e74726f6c5365745c73657276696365735c4d63536869656c6400}

    condition:
        $MZ at 0 and ($process_hacker_ascii or $process_hacker_unicode) and $mcshield_string
}