rule PEiD_02459_Upx_Lock_1_0___1_2____CyberDoom___Team_X___BoB___BobSoft_ {
  meta:
    description = "[Upx-Lock 1.0 - 1.2 -> CyberDoom / Team-X & BoB / BobSoft]"
    ep_only     = "true"

  strings:
    $a = { 60 E8 00 00 00 00 5D 81 ED 48 12 40 00 60 E8 2B 03 00 00 61 }

  condition:
    $a
}