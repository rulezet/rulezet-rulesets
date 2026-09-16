rule TTP_XOR_QUAD_CurrentVersionRun_1be1 {
  strings:
    $key_1be1 = { 48 8e [2] 6c 80 [2] 47 ac [2] 69 8e [2] 7d 95 [2] 72 8f [2] 6c 92 [2] 6e 93 [2] 75 95 [2] 69 92 [2] 75 bd }

  condition:
    any of them
}