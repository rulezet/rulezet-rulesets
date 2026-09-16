rule PEiD_01718_PKLITE32_1_1_ {
  meta:
    description = "[PKLITE32 1.1]"
    ep_only     = "true"

  strings:
    $a = "PKLITE32 Copyright 1"

  condition:
    $a
}