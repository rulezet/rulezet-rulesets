rule TTP_XOR_QUAD_CurrentVersionRun_76e1 {
  strings:
    $key_76e1 = { 25 8e [2] 01 80 [2] 2a ac [2] 04 8e [2] 10 95 [2] 1f 8f [2] 01 92 [2] 03 93 [2] 18 95 [2] 04 92 [2] 18 bd }

  condition:
    any of them
}