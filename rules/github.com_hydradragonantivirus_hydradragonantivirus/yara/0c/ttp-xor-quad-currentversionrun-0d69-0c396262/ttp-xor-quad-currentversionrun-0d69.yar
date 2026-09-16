rule TTP_XOR_QUAD_CurrentVersionRun_0d69 {
  strings:
    $key_0d69 = { 5e 06 [2] 7a 08 [2] 51 24 [2] 7f 06 [2] 6b 1d [2] 64 07 [2] 7a 1a [2] 78 1b [2] 63 1d [2] 7f 1a [2] 63 35 }

  condition:
    any of them
}