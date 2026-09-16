rule TTP_XOR_QUAD_CurrentVersionRun_908c {
  strings:
    $key_908c = { c3 e3 [2] e7 ed [2] cc c1 [2] e2 e3 [2] f6 f8 [2] f9 e2 [2] e7 ff [2] e5 fe [2] fe f8 [2] e2 ff [2] fe d0 }

  condition:
    any of them
}