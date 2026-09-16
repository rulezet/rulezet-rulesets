rule TTP_XOR_QUAD_CurrentVersionRun_68e1 {
  strings:
    $key_68e1 = { 3b 8e [2] 1f 80 [2] 34 ac [2] 1a 8e [2] 0e 95 [2] 01 8f [2] 1f 92 [2] 1d 93 [2] 06 95 [2] 1a 92 [2] 06 bd }

  condition:
    any of them
}