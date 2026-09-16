rule TTP_XOR_QUAD_CurrentVersionRun_07e1 {
  strings:
    $key_07e1 = { 54 8e [2] 70 80 [2] 5b ac [2] 75 8e [2] 61 95 [2] 6e 8f [2] 70 92 [2] 72 93 [2] 69 95 [2] 75 92 [2] 69 bd }

  condition:
    any of them
}