rule TTP_XOR_QUAD_CurrentVersionRun_e564 {
  strings:
    $key_e564 = { b6 0b [2] 92 05 [2] b9 29 [2] 97 0b [2] 83 10 [2] 8c 0a [2] 92 17 [2] 90 16 [2] 8b 10 [2] 97 17 [2] 8b 38 }

  condition:
    any of them
}