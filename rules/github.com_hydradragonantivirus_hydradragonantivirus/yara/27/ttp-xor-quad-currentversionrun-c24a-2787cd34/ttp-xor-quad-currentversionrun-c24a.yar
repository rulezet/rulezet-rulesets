rule TTP_XOR_QUAD_CurrentVersionRun_c24a {
  strings:
    $key_c24a = { 91 25 [2] b5 2b [2] 9e 07 [2] b0 25 [2] a4 3e [2] ab 24 [2] b5 39 [2] b7 38 [2] ac 3e [2] b0 39 [2] ac 16 }

  condition:
    any of them
}