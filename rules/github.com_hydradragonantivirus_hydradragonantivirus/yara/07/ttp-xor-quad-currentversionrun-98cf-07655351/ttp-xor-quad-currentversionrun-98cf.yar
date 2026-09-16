rule TTP_XOR_QUAD_CurrentVersionRun_98cf {
  strings:
    $key_98cf = { cb a0 [2] ef ae [2] c4 82 [2] ea a0 [2] fe bb [2] f1 a1 [2] ef bc [2] ed bd [2] f6 bb [2] ea bc [2] f6 93 }

  condition:
    any of them
}