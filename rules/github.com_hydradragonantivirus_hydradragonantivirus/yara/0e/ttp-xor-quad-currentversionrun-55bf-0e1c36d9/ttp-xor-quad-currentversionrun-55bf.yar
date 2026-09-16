rule TTP_XOR_QUAD_CurrentVersionRun_55bf {
  strings:
    $key_55bf = { 06 d0 [2] 22 de [2] 09 f2 [2] 27 d0 [2] 33 cb [2] 3c d1 [2] 22 cc [2] 20 cd [2] 3b cb [2] 27 cc [2] 3b e3 }

  condition:
    any of them
}