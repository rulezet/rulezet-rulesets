rule TTP_XOR_QUAD_CurrentVersionRun_ac92 {
  strings:
    $key_ac92 = { ff fd [2] db f3 [2] f0 df [2] de fd [2] ca e6 [2] c5 fc [2] db e1 [2] d9 e0 [2] c2 e6 [2] de e1 [2] c2 ce }

  condition:
    any of them
}