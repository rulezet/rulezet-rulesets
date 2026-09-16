rule PEiD_00192_AsCrypt_v0_1____SToRM____3_ {
  meta:
    description = "[AsCrypt v0.1 -> SToRM - #3]"
    ep_only     = "false"

  strings:
    $a = { 80 ?? ?? ?? 83 ?? ?? ?? ?? 90 90 90 51 ?? ?? ?? 01 00 00 00 83 ?? ?? E2 }

  condition:
    $a
}