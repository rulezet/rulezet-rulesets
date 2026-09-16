rule TTP_XOR_QUAD_CurrentVersionRun_f978 {
  strings:
    $key_f978 = { aa 17 [2] 8e 19 [2] a5 35 [2] 8b 17 [2] 9f 0c [2] 90 16 [2] 8e 0b [2] 8c 0a [2] 97 0c [2] 8b 0b [2] 97 24 }

  condition:
    any of them
}