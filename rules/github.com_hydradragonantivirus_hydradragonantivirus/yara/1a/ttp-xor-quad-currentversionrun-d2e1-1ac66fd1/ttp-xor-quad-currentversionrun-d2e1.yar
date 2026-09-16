rule TTP_XOR_QUAD_CurrentVersionRun_d2e1 {
  strings:
    $key_d2e1 = { 81 8e [2] a5 80 [2] 8e ac [2] a0 8e [2] b4 95 [2] bb 8f [2] a5 92 [2] a7 93 [2] bc 95 [2] a0 92 [2] bc bd }

  condition:
    any of them
}