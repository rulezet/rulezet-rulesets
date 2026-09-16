rule TTP_XOR_QUAD_CurrentVersionRun_f95a {
  strings:
    $key_f95a = { aa 35 [2] 8e 3b [2] a5 17 [2] 8b 35 [2] 9f 2e [2] 90 34 [2] 8e 29 [2] 8c 28 [2] 97 2e [2] 8b 29 [2] 97 06 }

  condition:
    any of them
}