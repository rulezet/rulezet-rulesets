rule TTP_XOR_QUAD_CurrentVersionRun_65e1 {
  strings:
    $key_65e1 = { 36 8e [2] 12 80 [2] 39 ac [2] 17 8e [2] 03 95 [2] 0c 8f [2] 12 92 [2] 10 93 [2] 0b 95 [2] 17 92 [2] 0b bd }

  condition:
    any of them
}