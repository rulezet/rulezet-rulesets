rule TTP_XOR_QUAD_CurrentVersionRun_8ccd {
  strings:
    $key_8ccd = { df a2 [2] fb ac [2] d0 80 [2] fe a2 [2] ea b9 [2] e5 a3 [2] fb be [2] f9 bf [2] e2 b9 [2] fe be [2] e2 91 }

  condition:
    any of them
}