rule TTP_XOR_QUAD_CurrentVersionRun_bebf {
  strings:
    $key_bebf = { ed d0 [2] c9 de [2] e2 f2 [2] cc d0 [2] d8 cb [2] d7 d1 [2] c9 cc [2] cb cd [2] d0 cb [2] cc cc [2] d0 e3 }

  condition:
    any of them
}