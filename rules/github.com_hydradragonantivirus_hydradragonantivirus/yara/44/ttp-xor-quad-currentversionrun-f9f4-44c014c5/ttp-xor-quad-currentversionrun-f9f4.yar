rule TTP_XOR_QUAD_CurrentVersionRun_f9f4 {
  strings:
    $key_f9f4 = { aa 9b [2] 8e 95 [2] a5 b9 [2] 8b 9b [2] 9f 80 [2] 90 9a [2] 8e 87 [2] 8c 86 [2] 97 80 [2] 8b 87 [2] 97 a8 }

  condition:
    any of them
}