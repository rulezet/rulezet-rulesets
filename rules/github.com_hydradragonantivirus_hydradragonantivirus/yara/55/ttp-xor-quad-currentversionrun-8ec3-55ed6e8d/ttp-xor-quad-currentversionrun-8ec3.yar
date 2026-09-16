rule TTP_XOR_QUAD_CurrentVersionRun_8ec3 {
  strings:
    $key_8ec3 = { dd ac [2] f9 a2 [2] d2 8e [2] fc ac [2] e8 b7 [2] e7 ad [2] f9 b0 [2] fb b1 [2] e0 b7 [2] fc b0 [2] e0 9f }

  condition:
    any of them
}