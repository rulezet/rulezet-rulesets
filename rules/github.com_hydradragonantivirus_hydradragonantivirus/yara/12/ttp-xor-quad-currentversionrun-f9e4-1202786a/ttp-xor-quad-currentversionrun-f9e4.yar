rule TTP_XOR_QUAD_CurrentVersionRun_f9e4 {
  strings:
    $key_f9e4 = { aa 8b [2] 8e 85 [2] a5 a9 [2] 8b 8b [2] 9f 90 [2] 90 8a [2] 8e 97 [2] 8c 96 [2] 97 90 [2] 8b 97 [2] 97 b8 }

  condition:
    any of them
}