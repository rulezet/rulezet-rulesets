rule TTP_XOR_QUAD_CurrentVersionRun_e096 {
  strings:
    $key_e096 = { b3 f9 [2] 97 f7 [2] bc db [2] 92 f9 [2] 86 e2 [2] 89 f8 [2] 97 e5 [2] 95 e4 [2] 8e e2 [2] 92 e5 [2] 8e ca }

  condition:
    any of them
}