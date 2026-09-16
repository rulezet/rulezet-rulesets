rule TTP_XOR_QUAD_CurrentVersionRun_dcb8 {
  strings:
    $key_dcb8 = { 8f d7 [2] ab d9 [2] 80 f5 [2] ae d7 [2] ba cc [2] b5 d6 [2] ab cb [2] a9 ca [2] b2 cc [2] ae cb [2] b2 e4 }

  condition:
    any of them
}