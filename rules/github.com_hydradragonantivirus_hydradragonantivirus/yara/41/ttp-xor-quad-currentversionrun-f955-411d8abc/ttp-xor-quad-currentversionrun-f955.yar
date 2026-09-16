rule TTP_XOR_QUAD_CurrentVersionRun_f955 {
  strings:
    $key_f955 = { aa 3a [2] 8e 34 [2] a5 18 [2] 8b 3a [2] 9f 21 [2] 90 3b [2] 8e 26 [2] 8c 27 [2] 97 21 [2] 8b 26 [2] 97 09 }

  condition:
    any of them
}