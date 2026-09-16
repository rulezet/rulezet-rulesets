rule TTP_XOR_QUAD_CurrentVersionRun_c546 {
  strings:
    $key_c546 = { 96 29 [2] b2 27 [2] 99 0b [2] b7 29 [2] a3 32 [2] ac 28 [2] b2 35 [2] b0 34 [2] ab 32 [2] b7 35 [2] ab 1a }

  condition:
    any of them
}