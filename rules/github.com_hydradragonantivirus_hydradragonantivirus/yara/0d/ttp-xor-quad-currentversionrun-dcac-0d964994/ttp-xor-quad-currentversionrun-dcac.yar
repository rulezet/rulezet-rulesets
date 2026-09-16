rule TTP_XOR_QUAD_CurrentVersionRun_dcac {
  strings:
    $key_dcac = { 8f c3 [2] ab cd [2] 80 e1 [2] ae c3 [2] ba d8 [2] b5 c2 [2] ab df [2] a9 de [2] b2 d8 [2] ae df [2] b2 f0 }

  condition:
    any of them
}