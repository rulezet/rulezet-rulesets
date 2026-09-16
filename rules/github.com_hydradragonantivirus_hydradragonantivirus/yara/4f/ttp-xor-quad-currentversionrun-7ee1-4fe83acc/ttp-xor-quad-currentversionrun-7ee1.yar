rule TTP_XOR_QUAD_CurrentVersionRun_7ee1 {
  strings:
    $key_7ee1 = { 2d 8e [2] 09 80 [2] 22 ac [2] 0c 8e [2] 18 95 [2] 17 8f [2] 09 92 [2] 0b 93 [2] 10 95 [2] 0c 92 [2] 10 bd }

  condition:
    any of them
}