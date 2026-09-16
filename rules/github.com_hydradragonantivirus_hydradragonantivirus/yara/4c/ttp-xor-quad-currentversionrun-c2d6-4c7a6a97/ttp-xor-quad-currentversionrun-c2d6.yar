rule TTP_XOR_QUAD_CurrentVersionRun_c2d6 {
  strings:
    $key_c2d6 = { 91 b9 [2] b5 b7 [2] 9e 9b [2] b0 b9 [2] a4 a2 [2] ab b8 [2] b5 a5 [2] b7 a4 [2] ac a2 [2] b0 a5 [2] ac 8a }

  condition:
    any of them
}