rule TTP_XOR_QUAD_CurrentVersionRun_0247 {
  strings:
    $key_0247 = { 51 28 [2] 75 26 [2] 5e 0a [2] 70 28 [2] 64 33 [2] 6b 29 [2] 75 34 [2] 77 35 [2] 6c 33 [2] 70 34 [2] 6c 1b }

  condition:
    any of them
}