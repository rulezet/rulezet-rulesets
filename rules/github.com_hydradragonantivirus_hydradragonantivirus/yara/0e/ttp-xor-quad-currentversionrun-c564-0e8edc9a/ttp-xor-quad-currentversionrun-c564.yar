rule TTP_XOR_QUAD_CurrentVersionRun_c564 {
  strings:
    $key_c564 = { 96 0b [2] b2 05 [2] 99 29 [2] b7 0b [2] a3 10 [2] ac 0a [2] b2 17 [2] b0 16 [2] ab 10 [2] b7 17 [2] ab 38 }

  condition:
    any of them
}