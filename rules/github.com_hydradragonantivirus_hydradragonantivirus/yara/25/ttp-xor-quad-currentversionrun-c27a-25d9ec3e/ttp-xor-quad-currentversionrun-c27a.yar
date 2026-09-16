rule TTP_XOR_QUAD_CurrentVersionRun_c27a {
  strings:
    $key_c27a = { 91 15 [2] b5 1b [2] 9e 37 [2] b0 15 [2] a4 0e [2] ab 14 [2] b5 09 [2] b7 08 [2] ac 0e [2] b0 09 [2] ac 26 }

  condition:
    any of them
}