rule TTP_XOR_QUAD_CurrentVersionRun_9dc9 {
  strings:
    $key_9dc9 = { ce a6 [2] ea a8 [2] c1 84 [2] ef a6 [2] fb bd [2] f4 a7 [2] ea ba [2] e8 bb [2] f3 bd [2] ef ba [2] f3 95 }

  condition:
    any of them
}