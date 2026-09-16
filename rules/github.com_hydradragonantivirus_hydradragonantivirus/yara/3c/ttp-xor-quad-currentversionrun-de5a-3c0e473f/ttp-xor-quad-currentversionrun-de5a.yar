rule TTP_XOR_QUAD_CurrentVersionRun_de5a {
  strings:
    $key_de5a = { 8d 35 [2] a9 3b [2] 82 17 [2] ac 35 [2] b8 2e [2] b7 34 [2] a9 29 [2] ab 28 [2] b0 2e [2] ac 29 [2] b0 06 }

  condition:
    any of them
}