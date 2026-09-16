rule TTP_XOR_QUAD_CurrentVersionRun_f91a {
  strings:
    $key_f91a = { aa 75 [2] 8e 7b [2] a5 57 [2] 8b 75 [2] 9f 6e [2] 90 74 [2] 8e 69 [2] 8c 68 [2] 97 6e [2] 8b 69 [2] 97 46 }

  condition:
    any of them
}