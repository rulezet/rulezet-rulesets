rule TTP_XOR_QUAD_CurrentVersionRun_f92b {
  strings:
    $key_f92b = { aa 44 [2] 8e 4a [2] a5 66 [2] 8b 44 [2] 9f 5f [2] 90 45 [2] 8e 58 [2] 8c 59 [2] 97 5f [2] 8b 58 [2] 97 77 }

  condition:
    any of them
}