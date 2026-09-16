rule TTP_XOR_QUAD_CurrentVersionRun_20e1 {
  strings:
    $key_20e1 = { 73 8e [2] 57 80 [2] 7c ac [2] 52 8e [2] 46 95 [2] 49 8f [2] 57 92 [2] 55 93 [2] 4e 95 [2] 52 92 [2] 4e bd }

  condition:
    any of them
}