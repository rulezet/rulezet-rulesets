rule TTP_XOR_QUAD_CurrentVersionRun_dcba {
  strings:
    $key_dcba = { 8f d5 [2] ab db [2] 80 f7 [2] ae d5 [2] ba ce [2] b5 d4 [2] ab c9 [2] a9 c8 [2] b2 ce [2] ae c9 [2] b2 e6 }

  condition:
    any of them
}