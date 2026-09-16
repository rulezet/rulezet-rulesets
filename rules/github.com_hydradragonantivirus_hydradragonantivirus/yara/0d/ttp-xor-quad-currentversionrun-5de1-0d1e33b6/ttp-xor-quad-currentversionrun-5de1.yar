rule TTP_XOR_QUAD_CurrentVersionRun_5de1 {
  strings:
    $key_5de1 = { 0e 8e [2] 2a 80 [2] 01 ac [2] 2f 8e [2] 3b 95 [2] 34 8f [2] 2a 92 [2] 28 93 [2] 33 95 [2] 2f 92 [2] 33 bd }

  condition:
    any of them
}