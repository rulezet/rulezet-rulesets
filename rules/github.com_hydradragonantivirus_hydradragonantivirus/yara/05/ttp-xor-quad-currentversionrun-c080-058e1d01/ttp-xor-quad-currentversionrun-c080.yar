rule TTP_XOR_QUAD_CurrentVersionRun_c080 {
  strings:
    $key_c080 = { 93 ef [2] b7 e1 [2] 9c cd [2] b2 ef [2] a6 f4 [2] a9 ee [2] b7 f3 [2] b5 f2 [2] ae f4 [2] b2 f3 [2] ae dc }

  condition:
    any of them
}