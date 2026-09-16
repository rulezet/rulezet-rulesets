rule TTP_XOR_QUAD_CurrentVersionRun_2fe1 {
  strings:
    $key_2fe1 = { 7c 8e [2] 58 80 [2] 73 ac [2] 5d 8e [2] 49 95 [2] 46 8f [2] 58 92 [2] 5a 93 [2] 41 95 [2] 5d 92 [2] 41 bd }

  condition:
    any of them
}