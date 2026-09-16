rule TTP_XOR_QUAD_CurrentVersionRun_e011 {
  strings:
    $key_e011 = { b3 7e [2] 97 70 [2] bc 5c [2] 92 7e [2] 86 65 [2] 89 7f [2] 97 62 [2] 95 63 [2] 8e 65 [2] 92 62 [2] 8e 4d }

  condition:
    any of them
}