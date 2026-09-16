rule TTP_XOR_QUAD_CurrentVersionRun_f92c {
  strings:
    $key_f92c = { aa 43 [2] 8e 4d [2] a5 61 [2] 8b 43 [2] 9f 58 [2] 90 42 [2] 8e 5f [2] 8c 5e [2] 97 58 [2] 8b 5f [2] 97 70 }

  condition:
    any of them
}