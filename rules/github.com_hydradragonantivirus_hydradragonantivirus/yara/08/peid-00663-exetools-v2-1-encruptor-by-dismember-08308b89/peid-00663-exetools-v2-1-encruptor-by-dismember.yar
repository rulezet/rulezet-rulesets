rule PEiD_00663_ExeTools_v2_1_Encruptor_by_DISMEMBER_ {
  meta:
    description = "[ExeTools v2.1 Encruptor by DISMEMBER]"
    ep_only     = "true"

  strings:
    $a = { E8 ?? ?? 5D 83 ?? ?? 1E 8C DA 83 ?? ?? 8E DA 8E C2 BB ?? ?? BA ?? ?? 85 D2 74 }

  condition:
    $a
}