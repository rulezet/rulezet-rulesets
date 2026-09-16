rule TTP_XOR_QUAD_CurrentVersionRun_0fe1 {
  strings:
    $key_0fe1 = { 5c 8e [2] 78 80 [2] 53 ac [2] 7d 8e [2] 69 95 [2] 66 8f [2] 78 92 [2] 7a 93 [2] 61 95 [2] 7d 92 [2] 61 bd }

  condition:
    any of them
}