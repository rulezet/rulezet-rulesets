rule TTP_XOR_QUAD_CurrentVersionRun_12bf {
  strings:
    $key_12bf = { 41 d0 [2] 65 de [2] 4e f2 [2] 60 d0 [2] 74 cb [2] 7b d1 [2] 65 cc [2] 67 cd [2] 7c cb [2] 60 cc [2] 7c e3 }

  condition:
    any of them
}