rule TTP_XOR_QUAD_CurrentVersionRun_7be1 {
  strings:
    $key_7be1 = { 28 8e [2] 0c 80 [2] 27 ac [2] 09 8e [2] 1d 95 [2] 12 8f [2] 0c 92 [2] 0e 93 [2] 15 95 [2] 09 92 [2] 15 bd }

  condition:
    any of them
}