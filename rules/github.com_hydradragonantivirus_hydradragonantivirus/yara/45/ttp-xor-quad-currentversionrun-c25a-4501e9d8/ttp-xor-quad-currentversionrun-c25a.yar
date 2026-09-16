rule TTP_XOR_QUAD_CurrentVersionRun_c25a {
  strings:
    $key_c25a = { 91 35 [2] b5 3b [2] 9e 17 [2] b0 35 [2] a4 2e [2] ab 34 [2] b5 29 [2] b7 28 [2] ac 2e [2] b0 29 [2] ac 06 }

  condition:
    any of them
}