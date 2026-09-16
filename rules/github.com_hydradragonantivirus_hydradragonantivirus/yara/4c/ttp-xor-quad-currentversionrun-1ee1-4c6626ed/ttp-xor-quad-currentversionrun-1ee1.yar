rule TTP_XOR_QUAD_CurrentVersionRun_1ee1 {
  strings:
    $key_1ee1 = { 4d 8e [2] 69 80 [2] 42 ac [2] 6c 8e [2] 78 95 [2] 77 8f [2] 69 92 [2] 6b 93 [2] 70 95 [2] 6c 92 [2] 70 bd }

  condition:
    any of them
}