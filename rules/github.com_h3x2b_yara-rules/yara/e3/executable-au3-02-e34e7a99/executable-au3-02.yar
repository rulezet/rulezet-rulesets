rule executable_au3_02 : info compiler autoit
{
    meta:
                description = "Match AU3 autoit executables"

    strings:
        $str_au3_01 = "AutoIt3"
        $str_au3_02 = "AutoIt v3"
        $str_au3_03 = "AU3!"

    condition:
        all of them
}