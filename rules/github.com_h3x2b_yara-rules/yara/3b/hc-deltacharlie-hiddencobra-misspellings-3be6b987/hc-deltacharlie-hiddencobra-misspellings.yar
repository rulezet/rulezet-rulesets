rule hc_deltacharlie__hiddencobra_misspellings: malware windows apt
{
  meta:
	description = "DDoS Misspelled Strings"
  strings:
        $STR1 = "Wating" wide ascii
        $STR2 = "Reamin" wide ascii
        $STR3 = "laptos" wide ascii

  condition:
        (uint16(0) == 0x5A4D
         or uint16(0) == 0xCFD0
         or uint16(0) == 0xC3D4
         or uint32(0) == 0x46445025
         or uint32(1) == 0x6674725C)
        and 2 of them
}