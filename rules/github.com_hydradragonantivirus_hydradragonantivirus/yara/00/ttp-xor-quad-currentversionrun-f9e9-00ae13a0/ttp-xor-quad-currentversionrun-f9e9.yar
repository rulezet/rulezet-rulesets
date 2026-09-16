rule TTP_XOR_QUAD_CurrentVersionRun_f9e9 {
  strings:
    $key_f9e9 = { aa 86 [2] 8e 88 [2] a5 a4 [2] 8b 86 [2] 9f 9d [2] 90 87 [2] 8e 9a [2] 8c 9b [2] 97 9d [2] 8b 9a [2] 97 b5 }

  condition:
    any of them
}