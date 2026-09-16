rule TTP_XOR_QUAD_CurrentVersionRun_dcab {
  strings:
    $key_dcab = { 8f c4 [2] ab ca [2] 80 e6 [2] ae c4 [2] ba df [2] b5 c5 [2] ab d8 [2] a9 d9 [2] b2 df [2] ae d8 [2] b2 f7 }

  condition:
    any of them
}