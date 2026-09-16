rule PEiD_02429_UPX_Protector_v1_0x_ {
  meta:
    description = "[UPX Protector v1.0x]"
    ep_only     = "true"

  strings:
    $a = { EB EC ?? ?? ?? ?? 8A 06 46 88 07 47 01 DB 75 07 }

  condition:
    $a
}