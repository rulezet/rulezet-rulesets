rule TTP_XOR_QUAD_CurrentVersionRun_c49d {
  strings:
    $key_c49d = { 97 f2 [2] b3 fc [2] 98 d0 [2] b6 f2 [2] a2 e9 [2] ad f3 [2] b3 ee [2] b1 ef [2] aa e9 [2] b6 ee [2] aa c1 }

  condition:
    any of them
}