rule TTP_XOR_QUAD_CurrentVersionRun_c2be {
  strings:
    $key_c2be = { 91 d1 [2] b5 df [2] 9e f3 [2] b0 d1 [2] a4 ca [2] ab d0 [2] b5 cd [2] b7 cc [2] ac ca [2] b0 cd [2] ac e2 }

  condition:
    any of them
}