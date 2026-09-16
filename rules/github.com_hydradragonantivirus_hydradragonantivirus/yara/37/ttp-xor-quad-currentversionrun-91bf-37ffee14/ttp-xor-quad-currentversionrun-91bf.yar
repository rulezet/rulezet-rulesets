rule TTP_XOR_QUAD_CurrentVersionRun_91bf {
  strings:
    $key_91bf = { c2 d0 [2] e6 de [2] cd f2 [2] e3 d0 [2] f7 cb [2] f8 d1 [2] e6 cc [2] e4 cd [2] ff cb [2] e3 cc [2] ff e3 }

  condition:
    any of them
}