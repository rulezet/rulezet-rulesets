rule TTP_XOR_QUAD_CurrentVersionRun_8cc8 {
  strings:
    $key_8cc8 = { df a7 [2] fb a9 [2] d0 85 [2] fe a7 [2] ea bc [2] e5 a6 [2] fb bb [2] f9 ba [2] e2 bc [2] fe bb [2] e2 94 }

  condition:
    any of them
}