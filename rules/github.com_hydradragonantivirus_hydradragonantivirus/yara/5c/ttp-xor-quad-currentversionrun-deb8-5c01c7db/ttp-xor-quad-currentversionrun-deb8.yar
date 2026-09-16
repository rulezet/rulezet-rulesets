rule TTP_XOR_QUAD_CurrentVersionRun_deb8 {
  strings:
    $key_deb8 = { 8d d7 [2] a9 d9 [2] 82 f5 [2] ac d7 [2] b8 cc [2] b7 d6 [2] a9 cb [2] ab ca [2] b0 cc [2] ac cb [2] b0 e4 }

  condition:
    any of them
}