rule PEiD_00099_aPack_v0_98b__exe__ {
  meta:
    description = "[aPack v0.98b (exe)]"
    ep_only     = "false"

  strings:
    $a = { 93 07 1F 05 ?? ?? 8E D0 BC ?? ?? EA }

  condition:
    $a
}