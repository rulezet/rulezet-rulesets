rule TTP_XOR_QUAD_CurrentVersionRun_8c92 {
  strings:
    $key_8c92 = { df fd [2] fb f3 [2] d0 df [2] fe fd [2] ea e6 [2] e5 fc [2] fb e1 [2] f9 e0 [2] e2 e6 [2] fe e1 [2] e2 ce }

  condition:
    any of them
}