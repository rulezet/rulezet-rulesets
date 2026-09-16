rule executable_au3_01 : info compiler autoit
{
    meta:
                description = "Match AU3 autoit executables"

    strings:
        $str_au3_01 = "AU3"
        $str_au3_02 = { A3 48 4B BE 98 6C 4A A9 99 4C 53 0A 86 D6 48 7D }

    condition:
        all of them
}