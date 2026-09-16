rule TTP_XOR_QUAD_CurrentVersionRun_dcb7 {
  strings:
    $key_dcb7 = { 8f d8 [2] ab d6 [2] 80 fa [2] ae d8 [2] ba c3 [2] b5 d9 [2] ab c4 [2] a9 c5 [2] b2 c3 [2] ae c4 [2] b2 eb }

  condition:
    any of them
}