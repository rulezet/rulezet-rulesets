rule TTP_XOR_QUAD_CurrentVersionRun_e072 {
  strings:
    $key_e072 = { b3 1d [2] 97 13 [2] bc 3f [2] 92 1d [2] 86 06 [2] 89 1c [2] 97 01 [2] 95 00 [2] 8e 06 [2] 92 01 [2] 8e 2e }

  condition:
    any of them
}