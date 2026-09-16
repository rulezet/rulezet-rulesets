rule TTP_XOR_QUAD_CurrentVersionRun_de46 {
  strings:
    $key_de46 = { 8d 29 [2] a9 27 [2] 82 0b [2] ac 29 [2] b8 32 [2] b7 28 [2] a9 35 [2] ab 34 [2] b0 32 [2] ac 35 [2] b0 1a }

  condition:
    any of them
}