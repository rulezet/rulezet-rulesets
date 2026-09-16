rule TTP_XOR_QUAD_CurrentVersionRun_73e1 {
  strings:
    $key_73e1 = { 20 8e [2] 04 80 [2] 2f ac [2] 01 8e [2] 15 95 [2] 1a 8f [2] 04 92 [2] 06 93 [2] 1d 95 [2] 01 92 [2] 1d bd }

  condition:
    any of them
}