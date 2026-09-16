rule TTP_XOR_QUAD_CurrentVersionRun_c2bf {
  strings:
    $key_c2bf = { 91 d0 [2] b5 de [2] 9e f2 [2] b0 d0 [2] a4 cb [2] ab d1 [2] b5 cc [2] b7 cd [2] ac cb [2] b0 cc [2] ac e3 }

  condition:
    any of them
}