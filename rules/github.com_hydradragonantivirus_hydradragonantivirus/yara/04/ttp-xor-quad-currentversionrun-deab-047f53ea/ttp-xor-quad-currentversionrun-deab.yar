rule TTP_XOR_QUAD_CurrentVersionRun_deab {
  strings:
    $key_deab = { 8d c4 [2] a9 ca [2] 82 e6 [2] ac c4 [2] b8 df [2] b7 c5 [2] a9 d8 [2] ab d9 [2] b0 df [2] ac d8 [2] b0 f7 }

  condition:
    any of them
}