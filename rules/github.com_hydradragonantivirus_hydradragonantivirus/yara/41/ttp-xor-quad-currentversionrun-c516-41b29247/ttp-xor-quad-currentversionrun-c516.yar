rule TTP_XOR_QUAD_CurrentVersionRun_c516 {
  strings:
    $key_c516 = { 96 79 [2] b2 77 [2] 99 5b [2] b7 79 [2] a3 62 [2] ac 78 [2] b2 65 [2] b0 64 [2] ab 62 [2] b7 65 [2] ab 4a }

  condition:
    any of them
}