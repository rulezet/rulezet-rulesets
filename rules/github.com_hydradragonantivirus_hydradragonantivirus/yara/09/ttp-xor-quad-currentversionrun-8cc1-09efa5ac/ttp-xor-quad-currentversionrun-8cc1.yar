rule TTP_XOR_QUAD_CurrentVersionRun_8cc1 {
  strings:
    $key_8cc1 = { df ae [2] fb a0 [2] d0 8c [2] fe ae [2] ea b5 [2] e5 af [2] fb b2 [2] f9 b3 [2] e2 b5 [2] fe b2 [2] e2 9d }

  condition:
    any of them
}