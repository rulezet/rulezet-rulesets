rule TTP_XOR_QUAD_CurrentVersionRun_c53a {
  strings:
    $key_c53a = { 96 55 [2] b2 5b [2] 99 77 [2] b7 55 [2] a3 4e [2] ac 54 [2] b2 49 [2] b0 48 [2] ab 4e [2] b7 49 [2] ab 66 }

  condition:
    any of them
}