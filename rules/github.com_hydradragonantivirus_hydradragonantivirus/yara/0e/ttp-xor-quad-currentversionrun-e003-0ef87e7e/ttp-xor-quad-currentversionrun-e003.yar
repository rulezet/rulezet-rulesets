rule TTP_XOR_QUAD_CurrentVersionRun_e003 {
  strings:
    $key_e003 = { b3 6c [2] 97 62 [2] bc 4e [2] 92 6c [2] 86 77 [2] 89 6d [2] 97 70 [2] 95 71 [2] 8e 77 [2] 92 70 [2] 8e 5f }

  condition:
    any of them
}