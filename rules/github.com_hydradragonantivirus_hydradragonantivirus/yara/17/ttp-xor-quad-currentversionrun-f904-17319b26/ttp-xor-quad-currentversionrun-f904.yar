rule TTP_XOR_QUAD_CurrentVersionRun_f904 {
  strings:
    $key_f904 = { aa 6b [2] 8e 65 [2] a5 49 [2] 8b 6b [2] 9f 70 [2] 90 6a [2] 8e 77 [2] 8c 76 [2] 97 70 [2] 8b 77 [2] 97 58 }

  condition:
    any of them
}