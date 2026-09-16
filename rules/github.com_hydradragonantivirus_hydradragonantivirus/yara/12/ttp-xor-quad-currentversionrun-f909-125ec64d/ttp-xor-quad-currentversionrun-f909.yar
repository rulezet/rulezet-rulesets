rule TTP_XOR_QUAD_CurrentVersionRun_f909 {
  strings:
    $key_f909 = { aa 66 [2] 8e 68 [2] a5 44 [2] 8b 66 [2] 9f 7d [2] 90 67 [2] 8e 7a [2] 8c 7b [2] 97 7d [2] 8b 7a [2] 97 55 }

  condition:
    any of them
}