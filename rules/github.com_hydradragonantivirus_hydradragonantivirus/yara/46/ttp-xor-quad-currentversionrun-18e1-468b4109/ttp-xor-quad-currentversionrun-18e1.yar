rule TTP_XOR_QUAD_CurrentVersionRun_18e1 {
  strings:
    $key_18e1 = { 4b 8e [2] 6f 80 [2] 44 ac [2] 6a 8e [2] 7e 95 [2] 71 8f [2] 6f 92 [2] 6d 93 [2] 76 95 [2] 6a 92 [2] 76 bd }

  condition:
    any of them
}