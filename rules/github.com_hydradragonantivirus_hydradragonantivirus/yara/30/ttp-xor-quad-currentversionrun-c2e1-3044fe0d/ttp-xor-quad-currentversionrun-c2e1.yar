rule TTP_XOR_QUAD_CurrentVersionRun_c2e1 {
  strings:
    $key_c2e1 = { 91 8e [2] b5 80 [2] 9e ac [2] b0 8e [2] a4 95 [2] ab 8f [2] b5 92 [2] b7 93 [2] ac 95 [2] b0 92 [2] ac bd }

  condition:
    any of them
}