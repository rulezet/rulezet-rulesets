rule TTP_XOR_QUAD_CurrentVersionRun_f95d {
  strings:
    $key_f95d = { aa 32 [2] 8e 3c [2] a5 10 [2] 8b 32 [2] 9f 29 [2] 90 33 [2] 8e 2e [2] 8c 2f [2] 97 29 [2] 8b 2e [2] 97 01 }

  condition:
    any of them
}