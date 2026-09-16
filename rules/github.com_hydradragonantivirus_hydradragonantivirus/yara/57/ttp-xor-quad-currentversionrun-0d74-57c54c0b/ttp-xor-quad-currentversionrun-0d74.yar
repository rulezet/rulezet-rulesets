rule TTP_XOR_QUAD_CurrentVersionRun_0d74 {
  strings:
    $key_0d74 = { 5e 1b [2] 7a 15 [2] 51 39 [2] 7f 1b [2] 6b 00 [2] 64 1a [2] 7a 07 [2] 78 06 [2] 63 00 [2] 7f 07 [2] 63 28 }

  condition:
    any of them
}