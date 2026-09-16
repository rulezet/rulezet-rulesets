rule TTP_XOR_QUAD_CurrentVersionRun_2ae1 {
  strings:
    $key_2ae1 = { 79 8e [2] 5d 80 [2] 76 ac [2] 58 8e [2] 4c 95 [2] 43 8f [2] 5d 92 [2] 5f 93 [2] 44 95 [2] 58 92 [2] 44 bd }

  condition:
    any of them
}