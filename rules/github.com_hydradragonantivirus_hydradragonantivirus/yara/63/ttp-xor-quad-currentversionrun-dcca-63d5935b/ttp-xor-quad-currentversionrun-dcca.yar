rule TTP_XOR_QUAD_CurrentVersionRun_dcca {
  strings:
    $key_dcca = { 8f a5 [2] ab ab [2] 80 87 [2] ae a5 [2] ba be [2] b5 a4 [2] ab b9 [2] a9 b8 [2] b2 be [2] ae b9 [2] b2 96 }

  condition:
    any of them
}