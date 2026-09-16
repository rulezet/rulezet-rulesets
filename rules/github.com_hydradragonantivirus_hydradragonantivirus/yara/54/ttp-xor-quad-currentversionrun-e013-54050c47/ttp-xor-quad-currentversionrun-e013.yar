rule TTP_XOR_QUAD_CurrentVersionRun_e013 {
  strings:
    $key_e013 = { b3 7c [2] 97 72 [2] bc 5e [2] 92 7c [2] 86 67 [2] 89 7d [2] 97 60 [2] 95 61 [2] 8e 67 [2] 92 60 [2] 8e 4f }

  condition:
    any of them
}