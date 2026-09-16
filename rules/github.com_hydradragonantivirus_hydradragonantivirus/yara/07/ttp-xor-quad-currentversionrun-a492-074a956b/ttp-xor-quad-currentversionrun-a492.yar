rule TTP_XOR_QUAD_CurrentVersionRun_a492 {
  strings:
    $key_a492 = { f7 fd [2] d3 f3 [2] f8 df [2] d6 fd [2] c2 e6 [2] cd fc [2] d3 e1 [2] d1 e0 [2] ca e6 [2] d6 e1 [2] ca ce }

  condition:
    any of them
}