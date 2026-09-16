rule TTP_XOR_QUAD_CurrentVersionRun_7ce1 {
  strings:
    $key_7ce1 = { 2f 8e [2] 0b 80 [2] 20 ac [2] 0e 8e [2] 1a 95 [2] 15 8f [2] 0b 92 [2] 09 93 [2] 12 95 [2] 0e 92 [2] 12 bd }

  condition:
    any of them
}