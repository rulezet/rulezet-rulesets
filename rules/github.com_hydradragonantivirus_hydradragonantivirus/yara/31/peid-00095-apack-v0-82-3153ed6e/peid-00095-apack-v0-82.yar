rule PEiD_00095_aPack_v0_82_ {
  meta:
    description = "[aPack v0.82]"
    ep_only     = "true"

  strings:
    $a = { 1E 06 8C CB BA ?? ?? 03 DA 8D ?? ?? ?? FC 33 F6 33 FF 48 4B 8E C0 8E DB }

  condition:
    $a
}