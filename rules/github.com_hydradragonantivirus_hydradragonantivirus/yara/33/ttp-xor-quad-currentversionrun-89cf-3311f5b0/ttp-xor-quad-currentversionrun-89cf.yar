rule TTP_XOR_QUAD_CurrentVersionRun_89cf {
  strings:
    $key_89cf = { da a0 [2] fe ae [2] d5 82 [2] fb a0 [2] ef bb [2] e0 a1 [2] fe bc [2] fc bd [2] e7 bb [2] fb bc [2] e7 93 }

  condition:
    any of them
}