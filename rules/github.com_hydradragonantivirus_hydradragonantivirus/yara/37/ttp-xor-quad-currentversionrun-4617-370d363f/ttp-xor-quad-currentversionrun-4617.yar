rule TTP_XOR_QUAD_CurrentVersionRun_4617 {
  strings:
    $key_4617 = { 15 78 [2] 31 76 [2] 1a 5a [2] 34 78 [2] 20 63 [2] 2f 79 [2] 31 64 [2] 33 65 [2] 28 63 [2] 34 64 [2] 28 4b }

  condition:
    any of them
}