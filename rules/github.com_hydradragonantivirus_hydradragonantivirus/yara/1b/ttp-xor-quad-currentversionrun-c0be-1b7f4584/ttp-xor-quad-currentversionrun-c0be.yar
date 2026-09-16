rule TTP_XOR_QUAD_CurrentVersionRun_c0be {
  strings:
    $key_c0be = { 93 d1 [2] b7 df [2] 9c f3 [2] b2 d1 [2] a6 ca [2] a9 d0 [2] b7 cd [2] b5 cc [2] ae ca [2] b2 cd [2] ae e2 }

  condition:
    any of them
}