rule TTP_XOR_QUAD_CurrentVersionRun_c56a {
  strings:
    $key_c56a = { 96 05 [2] b2 0b [2] 99 27 [2] b7 05 [2] a3 1e [2] ac 04 [2] b2 19 [2] b0 18 [2] ab 1e [2] b7 19 [2] ab 36 }

  condition:
    any of them
}