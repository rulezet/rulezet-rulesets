rule TTP_XOR_QUAD_CurrentVersionRun_dbab {
  strings:
    $key_dbab = { 88 c4 [2] ac ca [2] 87 e6 [2] a9 c4 [2] bd df [2] b2 c5 [2] ac d8 [2] ae d9 [2] b5 df [2] a9 d8 [2] b5 f7 }

  condition:
    any of them
}