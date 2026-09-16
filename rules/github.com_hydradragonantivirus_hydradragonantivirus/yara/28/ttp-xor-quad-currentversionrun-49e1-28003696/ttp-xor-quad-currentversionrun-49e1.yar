rule TTP_XOR_QUAD_CurrentVersionRun_49e1 {
  strings:
    $key_49e1 = { 1a 8e [2] 3e 80 [2] 15 ac [2] 3b 8e [2] 2f 95 [2] 20 8f [2] 3e 92 [2] 3c 93 [2] 27 95 [2] 3b 92 [2] 27 bd }

  condition:
    any of them
}