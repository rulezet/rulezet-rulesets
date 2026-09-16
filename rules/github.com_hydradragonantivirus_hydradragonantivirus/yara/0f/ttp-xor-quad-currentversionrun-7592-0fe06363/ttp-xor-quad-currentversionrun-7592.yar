rule TTP_XOR_QUAD_CurrentVersionRun_7592 {
  strings:
    $key_7592 = { 26 fd [2] 02 f3 [2] 29 df [2] 07 fd [2] 13 e6 [2] 1c fc [2] 02 e1 [2] 00 e0 [2] 1b e6 [2] 07 e1 [2] 1b ce }

  condition:
    any of them
}