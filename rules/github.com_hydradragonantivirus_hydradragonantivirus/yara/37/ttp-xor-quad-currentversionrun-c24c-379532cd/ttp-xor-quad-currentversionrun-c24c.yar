rule TTP_XOR_QUAD_CurrentVersionRun_c24c {
  strings:
    $key_c24c = { 91 23 [2] b5 2d [2] 9e 01 [2] b0 23 [2] a4 38 [2] ab 22 [2] b5 3f [2] b7 3e [2] ac 38 [2] b0 3f [2] ac 10 }

  condition:
    any of them
}