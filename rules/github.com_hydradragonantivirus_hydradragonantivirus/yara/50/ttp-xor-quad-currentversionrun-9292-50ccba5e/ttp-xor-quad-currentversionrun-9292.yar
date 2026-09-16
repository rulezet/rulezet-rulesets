rule TTP_XOR_QUAD_CurrentVersionRun_9292 {
  strings:
    $key_9292 = { c1 fd [2] e5 f3 [2] ce df [2] e0 fd [2] f4 e6 [2] fb fc [2] e5 e1 [2] e7 e0 [2] fc e6 [2] e0 e1 [2] fc ce }

  condition:
    any of them
}