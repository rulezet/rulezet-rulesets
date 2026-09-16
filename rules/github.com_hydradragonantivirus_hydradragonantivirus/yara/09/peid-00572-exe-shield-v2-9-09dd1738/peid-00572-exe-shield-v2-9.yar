rule PEiD_00572_Exe_Shield_v2_9_ {
  meta:
    description = "[Exe Shield v2.9]"
    ep_only     = "true"

  strings:
    $a = { 60 E8 00 00 00 00 5D 81 ED 0B 20 40 00 B9 EB 08 00 00 8D BD 53 20 40 00 8B F7 AC ?? ?? ?? F8 }

  condition:
    $a
}