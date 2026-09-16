rule TTP_XOR_QUAD_CurrentVersionRun_908d {
  strings:
    $key_908d = { c3 e2 [2] e7 ec [2] cc c0 [2] e2 e2 [2] f6 f9 [2] f9 e3 [2] e7 fe [2] e5 ff [2] fe f9 [2] e2 fe [2] fe d1 }

  condition:
    any of them
}