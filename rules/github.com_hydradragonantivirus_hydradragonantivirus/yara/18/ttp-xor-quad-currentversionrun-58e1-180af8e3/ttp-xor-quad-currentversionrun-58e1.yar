rule TTP_XOR_QUAD_CurrentVersionRun_58e1 {
  strings:
    $key_58e1 = { 0b 8e [2] 2f 80 [2] 04 ac [2] 2a 8e [2] 3e 95 [2] 31 8f [2] 2f 92 [2] 2d 93 [2] 36 95 [2] 2a 92 [2] 36 bd }

  condition:
    any of them
}