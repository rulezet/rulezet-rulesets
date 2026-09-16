rule TTP_XOR_QUAD_CurrentVersionRun_e07c {
  strings:
    $key_e07c = { b3 13 [2] 97 1d [2] bc 31 [2] 92 13 [2] 86 08 [2] 89 12 [2] 97 0f [2] 95 0e [2] 8e 08 [2] 92 0f [2] 8e 20 }

  condition:
    any of them
}