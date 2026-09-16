rule TTP_XOR_QUAD_CurrentVersionRun_25e1 {
  strings:
    $key_25e1 = { 76 8e [2] 52 80 [2] 79 ac [2] 57 8e [2] 43 95 [2] 4c 8f [2] 52 92 [2] 50 93 [2] 4b 95 [2] 57 92 [2] 4b bd }

  condition:
    any of them
}