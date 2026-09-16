rule PEiD_02471_UPXFreak_V0_1____HMX0101_ {
  meta:
    description = "[UPXFreak V0.1 -> HMX0101]"
    ep_only     = "true"

  strings:
    $a = { BE ?? ?? ?? ?? 83 C6 01 FF E6 00 00 }

  condition:
    $a
}