rule TTP_XOR_QUAD_CurrentVersionRun_f5be {
  strings:
    $key_f5be = { a6 d1 [2] 82 df [2] a9 f3 [2] 87 d1 [2] 93 ca [2] 9c d0 [2] 82 cd [2] 80 cc [2] 9b ca [2] 87 cd [2] 9b e2 }

  condition:
    any of them
}