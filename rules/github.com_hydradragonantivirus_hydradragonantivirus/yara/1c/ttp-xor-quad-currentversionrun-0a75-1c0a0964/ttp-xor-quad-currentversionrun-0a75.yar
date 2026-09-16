rule TTP_XOR_QUAD_CurrentVersionRun_0a75 {
  strings:
    $key_0a75 = { 59 1a [2] 7d 14 [2] 56 38 [2] 78 1a [2] 6c 01 [2] 63 1b [2] 7d 06 [2] 7f 07 [2] 64 01 [2] 78 06 [2] 64 29 }

  condition:
    any of them
}