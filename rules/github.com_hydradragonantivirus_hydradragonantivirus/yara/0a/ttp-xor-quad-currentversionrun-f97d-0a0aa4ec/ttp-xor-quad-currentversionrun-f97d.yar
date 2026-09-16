rule TTP_XOR_QUAD_CurrentVersionRun_f97d {
  strings:
    $key_f97d = { aa 12 [2] 8e 1c [2] a5 30 [2] 8b 12 [2] 9f 09 [2] 90 13 [2] 8e 0e [2] 8c 0f [2] 97 09 [2] 8b 0e [2] 97 21 }

  condition:
    any of them
}