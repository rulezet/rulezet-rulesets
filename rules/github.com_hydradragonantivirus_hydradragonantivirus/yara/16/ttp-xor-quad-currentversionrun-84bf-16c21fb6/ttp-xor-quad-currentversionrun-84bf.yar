rule TTP_XOR_QUAD_CurrentVersionRun_84bf {
  strings:
    $key_84bf = { d7 d0 [2] f3 de [2] d8 f2 [2] f6 d0 [2] e2 cb [2] ed d1 [2] f3 cc [2] f1 cd [2] ea cb [2] f6 cc [2] ea e3 }

  condition:
    any of them
}