rule TTP_XOR_QUAD_CurrentVersionRun_8ec1 {
  strings:
    $key_8ec1 = { dd ae [2] f9 a0 [2] d2 8c [2] fc ae [2] e8 b5 [2] e7 af [2] f9 b2 [2] fb b3 [2] e0 b5 [2] fc b2 [2] e0 9d }

  condition:
    any of them
}