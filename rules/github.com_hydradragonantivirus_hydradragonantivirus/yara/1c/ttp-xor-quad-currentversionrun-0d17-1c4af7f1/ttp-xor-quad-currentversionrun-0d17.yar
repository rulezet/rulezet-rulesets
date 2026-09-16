rule TTP_XOR_QUAD_CurrentVersionRun_0d17 {
  strings:
    $key_0d17 = { 5e 78 [2] 7a 76 [2] 51 5a [2] 7f 78 [2] 6b 63 [2] 64 79 [2] 7a 64 [2] 78 65 [2] 63 63 [2] 7f 64 [2] 63 4b }

  condition:
    any of them
}