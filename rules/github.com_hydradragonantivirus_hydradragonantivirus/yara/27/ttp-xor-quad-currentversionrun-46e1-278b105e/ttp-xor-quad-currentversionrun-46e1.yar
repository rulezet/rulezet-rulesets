rule TTP_XOR_QUAD_CurrentVersionRun_46e1 {
  strings:
    $key_46e1 = { 15 8e [2] 31 80 [2] 1a ac [2] 34 8e [2] 20 95 [2] 2f 8f [2] 31 92 [2] 33 93 [2] 28 95 [2] 34 92 [2] 28 bd }

  condition:
    any of them
}