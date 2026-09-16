rule TTP_XOR_QUAD_CurrentVersionRun_9daa {
  strings:
    $key_9daa = { ce c5 [2] ea cb [2] c1 e7 [2] ef c5 [2] fb de [2] f4 c4 [2] ea d9 [2] e8 d8 [2] f3 de [2] ef d9 [2] f3 f6 }

  condition:
    any of them
}