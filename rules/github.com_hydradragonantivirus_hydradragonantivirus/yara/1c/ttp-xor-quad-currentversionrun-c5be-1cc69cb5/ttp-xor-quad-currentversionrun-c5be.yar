rule TTP_XOR_QUAD_CurrentVersionRun_c5be {
  strings:
    $key_c5be = { 96 d1 [2] b2 df [2] 99 f3 [2] b7 d1 [2] a3 ca [2] ac d0 [2] b2 cd [2] b0 cc [2] ab ca [2] b7 cd [2] ab e2 }

  condition:
    any of them
}