rule TTP_XOR_QUAD_CurrentVersionRun_f97a {
  strings:
    $key_f97a = { aa 15 [2] 8e 1b [2] a5 37 [2] 8b 15 [2] 9f 0e [2] 90 14 [2] 8e 09 [2] 8c 08 [2] 97 0e [2] 8b 09 [2] 97 26 }

  condition:
    any of them
}