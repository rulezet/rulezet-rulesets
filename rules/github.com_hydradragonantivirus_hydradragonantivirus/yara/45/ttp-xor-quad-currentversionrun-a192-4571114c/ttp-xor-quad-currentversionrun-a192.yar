rule TTP_XOR_QUAD_CurrentVersionRun_a192 {
  strings:
    $key_a192 = { f2 fd [2] d6 f3 [2] fd df [2] d3 fd [2] c7 e6 [2] c8 fc [2] d6 e1 [2] d4 e0 [2] cf e6 [2] d3 e1 [2] cf ce }

  condition:
    any of them
}