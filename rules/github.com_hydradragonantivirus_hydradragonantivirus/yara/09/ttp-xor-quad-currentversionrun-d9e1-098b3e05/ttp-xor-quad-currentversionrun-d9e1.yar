rule TTP_XOR_QUAD_CurrentVersionRun_d9e1 {
  strings:
    $key_d9e1 = { 8a 8e [2] ae 80 [2] 85 ac [2] ab 8e [2] bf 95 [2] b0 8f [2] ae 92 [2] ac 93 [2] b7 95 [2] ab 92 [2] b7 bd }

  condition:
    any of them
}