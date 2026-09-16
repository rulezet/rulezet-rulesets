rule TTP_XOR_QUAD_CurrentVersionRun_c23a {
  strings:
    $key_c23a = { 91 55 [2] b5 5b [2] 9e 77 [2] b0 55 [2] a4 4e [2] ab 54 [2] b5 49 [2] b7 48 [2] ac 4e [2] b0 49 [2] ac 66 }

  condition:
    any of them
}