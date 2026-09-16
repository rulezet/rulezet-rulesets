rule TTP_XOR_QUAD_CurrentVersionRun_8ca3 {
  strings:
    $key_8ca3 = { df cc [2] fb c2 [2] d0 ee [2] fe cc [2] ea d7 [2] e5 cd [2] fb d0 [2] f9 d1 [2] e2 d7 [2] fe d0 [2] e2 ff }

  condition:
    any of them
}