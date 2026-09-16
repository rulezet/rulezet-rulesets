rule TTP_XOR_QUAD_CurrentVersionRun_4ee1 {
  strings:
    $key_4ee1 = { 1d 8e [2] 39 80 [2] 12 ac [2] 3c 8e [2] 28 95 [2] 27 8f [2] 39 92 [2] 3b 93 [2] 20 95 [2] 3c 92 [2] 20 bd }

  condition:
    any of them
}