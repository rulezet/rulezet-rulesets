rule TTP_XOR_QUAD_CurrentVersionRun_f914 {
  strings:
    $key_f914 = { aa 7b [2] 8e 75 [2] a5 59 [2] 8b 7b [2] 9f 60 [2] 90 7a [2] 8e 67 [2] 8c 66 [2] 97 60 [2] 8b 67 [2] 97 48 }

  condition:
    any of them
}