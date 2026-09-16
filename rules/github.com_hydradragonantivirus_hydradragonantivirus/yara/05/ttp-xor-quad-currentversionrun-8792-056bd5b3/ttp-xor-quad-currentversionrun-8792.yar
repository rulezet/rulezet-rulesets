rule TTP_XOR_QUAD_CurrentVersionRun_8792 {
  strings:
    $key_8792 = { d4 fd [2] f0 f3 [2] db df [2] f5 fd [2] e1 e6 [2] ee fc [2] f0 e1 [2] f2 e0 [2] e9 e6 [2] f5 e1 [2] e9 ce }

  condition:
    any of them
}