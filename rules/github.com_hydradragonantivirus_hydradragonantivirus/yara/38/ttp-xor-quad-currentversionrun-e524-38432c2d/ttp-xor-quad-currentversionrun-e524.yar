rule TTP_XOR_QUAD_CurrentVersionRun_e524 {
  strings:
    $key_e524 = { b6 4b [2] 92 45 [2] b9 69 [2] 97 4b [2] 83 50 [2] 8c 4a [2] 92 57 [2] 90 56 [2] 8b 50 [2] 97 57 [2] 8b 78 }

  condition:
    any of them
}