rule TTP_XOR_QUAD_CurrentVersionRun_90b5 {
  strings:
    $key_90b5 = { c3 da [2] e7 d4 [2] cc f8 [2] e2 da [2] f6 c1 [2] f9 db [2] e7 c6 [2] e5 c7 [2] fe c1 [2] e2 c6 [2] fe e9 }

  condition:
    any of them
}