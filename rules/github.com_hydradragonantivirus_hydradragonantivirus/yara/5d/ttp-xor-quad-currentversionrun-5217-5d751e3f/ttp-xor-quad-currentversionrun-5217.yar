rule TTP_XOR_QUAD_CurrentVersionRun_5217 {
  strings:
    $key_5217 = { 01 78 [2] 25 76 [2] 0e 5a [2] 20 78 [2] 34 63 [2] 3b 79 [2] 25 64 [2] 27 65 [2] 3c 63 [2] 20 64 [2] 3c 4b }

  condition:
    any of them
}