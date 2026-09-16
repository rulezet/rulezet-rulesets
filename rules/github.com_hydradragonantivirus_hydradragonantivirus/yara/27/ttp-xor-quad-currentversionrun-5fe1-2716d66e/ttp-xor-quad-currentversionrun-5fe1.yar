rule TTP_XOR_QUAD_CurrentVersionRun_5fe1 {
  strings:
    $key_5fe1 = { 0c 8e [2] 28 80 [2] 03 ac [2] 2d 8e [2] 39 95 [2] 36 8f [2] 28 92 [2] 2a 93 [2] 31 95 [2] 2d 92 [2] 31 bd }

  condition:
    any of them
}