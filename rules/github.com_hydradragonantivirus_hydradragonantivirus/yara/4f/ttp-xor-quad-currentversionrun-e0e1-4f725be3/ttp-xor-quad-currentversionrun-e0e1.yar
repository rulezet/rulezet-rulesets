rule TTP_XOR_QUAD_CurrentVersionRun_e0e1 {
  strings:
    $key_e0e1 = { b3 8e [2] 97 80 [2] bc ac [2] 92 8e [2] 86 95 [2] 89 8f [2] 97 92 [2] 95 93 [2] 8e 95 [2] 92 92 [2] 8e bd }

  condition:
    any of them
}