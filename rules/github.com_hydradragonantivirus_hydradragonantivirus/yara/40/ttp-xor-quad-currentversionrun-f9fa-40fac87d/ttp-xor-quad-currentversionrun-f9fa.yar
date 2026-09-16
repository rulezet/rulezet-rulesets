rule TTP_XOR_QUAD_CurrentVersionRun_f9fa {
  strings:
    $key_f9fa = { aa 95 [2] 8e 9b [2] a5 b7 [2] 8b 95 [2] 9f 8e [2] 90 94 [2] 8e 89 [2] 8c 88 [2] 97 8e [2] 8b 89 [2] 97 a6 }

  condition:
    any of them
}