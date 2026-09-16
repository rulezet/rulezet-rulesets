import "pe"
rule PEiD_01440_Packed_with__PKLITE_v1_50_with_CRC_check__1__ {
  meta:
    description = "[Packed with? PKLITE v1.50 with CRC check (1)]"
    ep_only     = "true"

  strings:
    $a = { 1F B4 09 BA ?? ?? CD 21 B8 ?? ?? CD 21 }

  condition:
    $a at pe.entry_point
}