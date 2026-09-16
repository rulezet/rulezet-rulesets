rule TTP_XOR_QUAD_CurrentVersionRun_dbb7 {
  strings:
    $key_dbb7 = { 88 d8 [2] ac d6 [2] 87 fa [2] a9 d8 [2] bd c3 [2] b2 d9 [2] ac c4 [2] ae c5 [2] b5 c3 [2] a9 c4 [2] b5 eb }

  condition:
    any of them
}