rule TTP_XOR_QUAD_CurrentVersionRun_f9f8 {
  strings:
    $key_f9f8 = { aa 97 [2] 8e 99 [2] a5 b5 [2] 8b 97 [2] 9f 8c [2] 90 96 [2] 8e 8b [2] 8c 8a [2] 97 8c [2] 8b 8b [2] 97 a4 }

  condition:
    any of them
}