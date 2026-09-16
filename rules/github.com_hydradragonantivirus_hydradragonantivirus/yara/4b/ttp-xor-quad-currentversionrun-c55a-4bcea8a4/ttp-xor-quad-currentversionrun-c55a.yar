rule TTP_XOR_QUAD_CurrentVersionRun_c55a {
  strings:
    $key_c55a = { 96 35 [2] b2 3b [2] 99 17 [2] b7 35 [2] a3 2e [2] ac 34 [2] b2 29 [2] b0 28 [2] ab 2e [2] b7 29 [2] ab 06 }

  condition:
    any of them
}