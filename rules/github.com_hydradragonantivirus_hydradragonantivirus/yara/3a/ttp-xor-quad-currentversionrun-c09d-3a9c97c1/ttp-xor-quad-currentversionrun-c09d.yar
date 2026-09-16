rule TTP_XOR_QUAD_CurrentVersionRun_c09d {
  strings:
    $key_c09d = { 93 f2 [2] b7 fc [2] 9c d0 [2] b2 f2 [2] a6 e9 [2] a9 f3 [2] b7 ee [2] b5 ef [2] ae e9 [2] b2 ee [2] ae c1 }

  condition:
    any of them
}