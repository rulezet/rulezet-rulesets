rule TTP_XOR_QUAD_CurrentVersionRun_e525 {
  strings:
    $key_e525 = { b6 4a [2] 92 44 [2] b9 68 [2] 97 4a [2] 83 51 [2] 8c 4b [2] 92 56 [2] 90 57 [2] 8b 51 [2] 97 56 [2] 8b 79 }

  condition:
    any of them
}