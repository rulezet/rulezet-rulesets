import "pe"
rule ORiEN_V2_12____Fisun_A_V_ {
  strings:
    $a0 = { E9 5D 01 00 00 CE D1 CE CD 0D }

  condition:
    $a0 at pe.entry_point
}