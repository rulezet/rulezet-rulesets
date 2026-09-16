rule TTP_XOR_QUAD_CurrentVersionRun_90bf {
  strings:
    $key_90bf = { c3 d0 [2] e7 de [2] cc f2 [2] e2 d0 [2] f6 cb [2] f9 d1 [2] e7 cc [2] e5 cd [2] fe cb [2] e2 cc [2] fe e3 }

  condition:
    any of them
}