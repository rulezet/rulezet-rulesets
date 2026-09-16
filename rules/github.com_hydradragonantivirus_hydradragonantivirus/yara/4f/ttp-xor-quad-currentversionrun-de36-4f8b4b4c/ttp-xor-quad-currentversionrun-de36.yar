rule TTP_XOR_QUAD_CurrentVersionRun_de36 {
  strings:
    $key_de36 = { 8d 59 [2] a9 57 [2] 82 7b [2] ac 59 [2] b8 42 [2] b7 58 [2] a9 45 [2] ab 44 [2] b0 42 [2] ac 45 [2] b0 6a }

  condition:
    any of them
}