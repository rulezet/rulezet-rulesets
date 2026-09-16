rule TTP_XOR_QUAD_CurrentVersionRun_4ce1 {
  strings:
    $key_4ce1 = { 1f 8e [2] 3b 80 [2] 10 ac [2] 3e 8e [2] 2a 95 [2] 25 8f [2] 3b 92 [2] 39 93 [2] 22 95 [2] 3e 92 [2] 22 bd }

  condition:
    any of them
}