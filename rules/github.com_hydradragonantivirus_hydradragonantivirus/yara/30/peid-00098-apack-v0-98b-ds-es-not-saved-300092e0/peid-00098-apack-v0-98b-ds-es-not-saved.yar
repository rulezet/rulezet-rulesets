rule PEiD_00098_aPack_v0_98b__DS___ES_not_saved__ {
  meta:
    description = "[aPack v0.98b (DS & ES not saved)]"
    ep_only     = "false"

  strings:
    $a = { 8C CB BA ?? ?? 03 DA FC 33 F6 33 FF 4B 8E DB 8D ?? ?? ?? 8E C0 B9 ?? ?? F3 A5 4A 75 }

  condition:
    $a
}