rule TTP_XOR_QUAD_CurrentVersionRun_1ce1 {
  strings:
    $key_1ce1 = { 4f 8e [2] 6b 80 [2] 40 ac [2] 6e 8e [2] 7a 95 [2] 75 8f [2] 6b 92 [2] 69 93 [2] 72 95 [2] 6e 92 [2] 72 bd }

  condition:
    any of them
}