import "pe"
rule UPX_Protector_v1_0x__2_ {
  strings:
    $a0 = { EB ?? ?? ?? ?? ?? 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB }

  condition:
    $a0 at pe.entry_point
}