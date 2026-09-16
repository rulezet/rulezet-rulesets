rule TTP_XOR_QUAD_CurrentVersionRun_e504 {
  strings:
    $key_e504 = { b6 6b [2] 92 65 [2] b9 49 [2] 97 6b [2] 83 70 [2] 8c 6a [2] 92 77 [2] 90 76 [2] 8b 70 [2] 97 77 [2] 8b 58 }

  condition:
    any of them
}