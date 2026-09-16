rule TTP_XOR_QUAD_CurrentVersionRun_c992 {
  strings:
    $key_c992 = { 9a fd [2] be f3 [2] 95 df [2] bb fd [2] af e6 [2] a0 fc [2] be e1 [2] bc e0 [2] a7 e6 [2] bb e1 [2] a7 ce }

  condition:
    any of them
}