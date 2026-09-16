rule TTP_XOR_QUAD_CurrentVersionRun_c523 {
  strings:
    $key_c523 = { 96 4c [2] b2 42 [2] 99 6e [2] b7 4c [2] a3 57 [2] ac 4d [2] b2 50 [2] b0 51 [2] ab 57 [2] b7 50 [2] ab 7f }

  condition:
    any of them
}