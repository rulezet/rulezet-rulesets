rule TTP_XOR_QUAD_CurrentVersionRun_22bf {
  strings:
    $key_22bf = { 71 d0 [2] 55 de [2] 7e f2 [2] 50 d0 [2] 44 cb [2] 4b d1 [2] 55 cc [2] 57 cd [2] 4c cb [2] 50 cc [2] 4c e3 }

  condition:
    any of them
}