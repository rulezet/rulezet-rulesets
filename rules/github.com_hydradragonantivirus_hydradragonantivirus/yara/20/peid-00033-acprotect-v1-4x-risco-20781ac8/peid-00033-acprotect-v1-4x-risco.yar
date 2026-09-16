rule PEiD_00033_ACProtect_V1_4X____risco_ {
  meta:
    description = "[ACProtect V1.4X -> risco]"
    ep_only     = "true"

  strings:
    $a = { 60 E8 01 00 00 00 7C 83 04 24 06 C3 }

  condition:
    $a
}