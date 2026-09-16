rule TTP_XOR_QUAD_CurrentVersionRun_0d47 {
  strings:
    $key_0d47 = { 5e 28 [2] 7a 26 [2] 51 0a [2] 7f 28 [2] 6b 33 [2] 64 29 [2] 7a 34 [2] 78 35 [2] 63 33 [2] 7f 34 [2] 63 1b }

  condition:
    any of them
}