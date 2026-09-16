rule TTP_XOR_QUAD_CurrentVersionRun_8cc4 {
  strings:
    $key_8cc4 = { df ab [2] fb a5 [2] d0 89 [2] fe ab [2] ea b0 [2] e5 aa [2] fb b7 [2] f9 b6 [2] e2 b0 [2] fe b7 [2] e2 98 }

  condition:
    any of them
}