rule TTP_XOR_QUAD_CurrentVersionRun_c21d {
  strings:
    $key_c21d = { 91 72 [2] b5 7c [2] 9e 50 [2] b0 72 [2] a4 69 [2] ab 73 [2] b5 6e [2] b7 6f [2] ac 69 [2] b0 6e [2] ac 41 }

  condition:
    any of them
}