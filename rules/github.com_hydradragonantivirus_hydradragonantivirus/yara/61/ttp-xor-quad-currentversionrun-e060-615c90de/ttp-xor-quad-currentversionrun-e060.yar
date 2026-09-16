rule TTP_XOR_QUAD_CurrentVersionRun_e060 {
  strings:
    $key_e060 = { b3 0f [2] 97 01 [2] bc 2d [2] 92 0f [2] 86 14 [2] 89 0e [2] 97 13 [2] 95 12 [2] 8e 14 [2] 92 13 [2] 8e 3c }

  condition:
    any of them
}