rule TTP_XOR_QUAD_CurrentVersionRun_0092 {
  strings:
    $key_0092 = { 53 fd [2] 77 f3 [2] 5c df [2] 72 fd [2] 66 e6 [2] 69 fc [2] 77 e1 [2] 75 e0 [2] 6e e6 [2] 72 e1 [2] 6e ce }

  condition:
    any of them
}