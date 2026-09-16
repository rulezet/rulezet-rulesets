rule TTP_XOR_QUAD_CurrentVersionRun_c7be {
  strings:
    $key_c7be = { 94 d1 [2] b0 df [2] 9b f3 [2] b5 d1 [2] a1 ca [2] ae d0 [2] b0 cd [2] b2 cc [2] a9 ca [2] b5 cd [2] a9 e2 }

  condition:
    any of them
}