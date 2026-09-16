rule TTP_XOR_QUAD_CurrentVersionRun_17e1 {
  strings:
    $key_17e1 = { 44 8e [2] 60 80 [2] 4b ac [2] 65 8e [2] 71 95 [2] 7e 8f [2] 60 92 [2] 62 93 [2] 79 95 [2] 65 92 [2] 79 bd }

  condition:
    any of them
}