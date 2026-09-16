rule TTP_XOR_QUAD_CurrentVersionRun_0c17 {
  strings:
    $key_0c17 = { 5f 78 [2] 7b 76 [2] 50 5a [2] 7e 78 [2] 6a 63 [2] 65 79 [2] 7b 64 [2] 79 65 [2] 62 63 [2] 7e 64 [2] 62 4b }

  condition:
    any of them
}