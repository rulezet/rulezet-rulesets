rule TTP_XOR_QUAD_CurrentVersionRun_8ec0 {
  strings:
    $key_8ec0 = { dd af [2] f9 a1 [2] d2 8d [2] fc af [2] e8 b4 [2] e7 ae [2] f9 b3 [2] fb b2 [2] e0 b4 [2] fc b3 [2] e0 9c }

  condition:
    any of them
}