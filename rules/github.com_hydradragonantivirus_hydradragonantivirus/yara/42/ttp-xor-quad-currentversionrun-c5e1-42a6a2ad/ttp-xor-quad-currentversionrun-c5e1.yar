rule TTP_XOR_QUAD_CurrentVersionRun_c5e1 {
  strings:
    $key_c5e1 = { 96 8e [2] b2 80 [2] 99 ac [2] b7 8e [2] a3 95 [2] ac 8f [2] b2 92 [2] b0 93 [2] ab 95 [2] b7 92 [2] ab bd }

  condition:
    any of them
}