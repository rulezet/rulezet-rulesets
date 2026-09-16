rule TTP_XOR_QUAD_CurrentVersionRun_a5bf {
  strings:
    $key_a5bf = { f6 d0 [2] d2 de [2] f9 f2 [2] d7 d0 [2] c3 cb [2] cc d1 [2] d2 cc [2] d0 cd [2] cb cb [2] d7 cc [2] cb e3 }

  condition:
    any of them
}