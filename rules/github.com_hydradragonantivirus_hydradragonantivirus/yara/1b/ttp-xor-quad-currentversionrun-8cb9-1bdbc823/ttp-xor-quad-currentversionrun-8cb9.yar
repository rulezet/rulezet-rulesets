rule TTP_XOR_QUAD_CurrentVersionRun_8cb9 {
  strings:
    $key_8cb9 = { df d6 [2] fb d8 [2] d0 f4 [2] fe d6 [2] ea cd [2] e5 d7 [2] fb ca [2] f9 cb [2] e2 cd [2] fe ca [2] e2 e5 }

  condition:
    any of them
}