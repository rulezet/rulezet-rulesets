rule TTP_XOR_QUAD_CurrentVersionRun_9dce {
  strings:
    $key_9dce = { ce a1 [2] ea af [2] c1 83 [2] ef a1 [2] fb ba [2] f4 a0 [2] ea bd [2] e8 bc [2] f3 ba [2] ef bd [2] f3 92 }

  condition:
    any of them
}