rule TTP_XOR_QUAD_CurrentVersionRun_f2bf {
  strings:
    $key_f2bf = { a1 d0 [2] 85 de [2] ae f2 [2] 80 d0 [2] 94 cb [2] 9b d1 [2] 85 cc [2] 87 cd [2] 9c cb [2] 80 cc [2] 9c e3 }

  condition:
    any of them
}