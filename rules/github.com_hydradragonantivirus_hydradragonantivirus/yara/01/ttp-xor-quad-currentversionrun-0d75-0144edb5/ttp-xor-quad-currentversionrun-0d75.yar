rule TTP_XOR_QUAD_CurrentVersionRun_0d75 {
  strings:
    $key_0d75 = { 5e 1a [2] 7a 14 [2] 51 38 [2] 7f 1a [2] 6b 01 [2] 64 1b [2] 7a 06 [2] 78 07 [2] 63 01 [2] 7f 06 [2] 63 29 }

  condition:
    any of them
}