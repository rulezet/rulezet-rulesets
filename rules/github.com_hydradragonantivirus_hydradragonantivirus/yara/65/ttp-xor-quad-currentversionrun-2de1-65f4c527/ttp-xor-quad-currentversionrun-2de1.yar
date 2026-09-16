rule TTP_XOR_QUAD_CurrentVersionRun_2de1 {
  strings:
    $key_2de1 = { 7e 8e [2] 5a 80 [2] 71 ac [2] 5f 8e [2] 4b 95 [2] 44 8f [2] 5a 92 [2] 58 93 [2] 43 95 [2] 5f 92 [2] 43 bd }

  condition:
    any of them
}