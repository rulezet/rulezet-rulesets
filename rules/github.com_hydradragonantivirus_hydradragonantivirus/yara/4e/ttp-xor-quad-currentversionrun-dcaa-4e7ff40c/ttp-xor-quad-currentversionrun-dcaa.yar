rule TTP_XOR_QUAD_CurrentVersionRun_dcaa {
  strings:
    $key_dcaa = { 8f c5 [2] ab cb [2] 80 e7 [2] ae c5 [2] ba de [2] b5 c4 [2] ab d9 [2] a9 d8 [2] b2 de [2] ae d9 [2] b2 f6 }

  condition:
    any of them
}