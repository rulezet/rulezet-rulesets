rule TTP_XOR_QUAD_CurrentVersionRun_3074 {
  strings:
    $key_3074 = { 63 1b [2] 47 15 [2] 6c 39 [2] 42 1b [2] 56 00 [2] 59 1a [2] 47 07 [2] 45 06 [2] 5e 00 [2] 42 07 [2] 5e 28 }

  condition:
    any of them
}