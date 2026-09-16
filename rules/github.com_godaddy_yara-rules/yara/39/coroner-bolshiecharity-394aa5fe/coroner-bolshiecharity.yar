rule coroner_bolshiecharity {
    meta:
        description = "Password extraction utility"

    strings:
        $mz = "MZ"
                $passwords = "chelsea\x0055555\x00angel1\x00hardcore\x00dexter\x00saved\x00112233\x00hallo\x00"

    condition:
        $mz at 0 and $passwords
}