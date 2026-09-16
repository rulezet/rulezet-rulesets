rule TTP_XOR_QUAD_CurrentVersionRun_e5f4 {
  strings:
    $key_e5f4 = { b6 9b [2] 92 95 [2] b9 b9 [2] 97 9b [2] 83 80 [2] 8c 9a [2] 92 87 [2] 90 86 [2] 8b 80 [2] 97 87 [2] 8b a8 }

  condition:
    any of them
}