rule PEiD_00193_AsCrypt_v0_1____SToRM___needs_to_be_added_ {
  meta:
    description = "[AsCrypt v0.1 -> SToRM - needs to be added]"
    ep_only     = "false"

  strings:
    $a = { 80 ?? ?? ?? 83 ?? ?? ?? ?? 90 90 90 83 ?? ?? E2 }

  condition:
    $a
}