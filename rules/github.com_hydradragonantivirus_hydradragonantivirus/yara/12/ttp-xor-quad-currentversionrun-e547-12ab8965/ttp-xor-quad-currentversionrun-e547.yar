rule TTP_XOR_QUAD_CurrentVersionRun_e547 {
  strings:
    $key_e547 = { b6 28 [2] 92 26 [2] b9 0a [2] 97 28 [2] 83 33 [2] 8c 29 [2] 92 34 [2] 90 35 [2] 8b 33 [2] 97 34 [2] 8b 1b }

  condition:
    any of them
}