rule TTP_XOR_QUAD_CurrentVersionRun_a692 {
  strings:
    $key_a692 = { f5 fd [2] d1 f3 [2] fa df [2] d4 fd [2] c0 e6 [2] cf fc [2] d1 e1 [2] d3 e0 [2] c8 e6 [2] d4 e1 [2] c8 ce }

  condition:
    any of them
}