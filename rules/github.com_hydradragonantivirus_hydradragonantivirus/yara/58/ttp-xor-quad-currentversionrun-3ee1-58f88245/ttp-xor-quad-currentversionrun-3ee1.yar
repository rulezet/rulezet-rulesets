rule TTP_XOR_QUAD_CurrentVersionRun_3ee1 {
  strings:
    $key_3ee1 = { 6d 8e [2] 49 80 [2] 62 ac [2] 4c 8e [2] 58 95 [2] 57 8f [2] 49 92 [2] 4b 93 [2] 50 95 [2] 4c 92 [2] 50 bd }

  condition:
    any of them
}