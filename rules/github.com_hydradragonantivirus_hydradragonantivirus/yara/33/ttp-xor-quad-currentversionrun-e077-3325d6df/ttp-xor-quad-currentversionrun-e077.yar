rule TTP_XOR_QUAD_CurrentVersionRun_e077 {
  strings:
    $key_e077 = { b3 18 [2] 97 16 [2] bc 3a [2] 92 18 [2] 86 03 [2] 89 19 [2] 97 04 [2] 95 05 [2] 8e 03 [2] 92 04 [2] 8e 2b }

  condition:
    any of them
}