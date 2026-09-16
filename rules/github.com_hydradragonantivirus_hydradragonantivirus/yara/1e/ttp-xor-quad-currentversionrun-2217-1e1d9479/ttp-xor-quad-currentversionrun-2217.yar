rule TTP_XOR_QUAD_CurrentVersionRun_2217 {
  strings:
    $key_2217 = { 71 78 [2] 55 76 [2] 7e 5a [2] 50 78 [2] 44 63 [2] 4b 79 [2] 55 64 [2] 57 65 [2] 4c 63 [2] 50 64 [2] 4c 4b }

  condition:
    any of them
}