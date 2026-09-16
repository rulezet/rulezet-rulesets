rule TTP_XOR_QUAD_CurrentVersionRun_28e1 {
  strings:
    $key_28e1 = { 7b 8e [2] 5f 80 [2] 74 ac [2] 5a 8e [2] 4e 95 [2] 41 8f [2] 5f 92 [2] 5d 93 [2] 46 95 [2] 5a 92 [2] 46 bd }

  condition:
    any of them
}