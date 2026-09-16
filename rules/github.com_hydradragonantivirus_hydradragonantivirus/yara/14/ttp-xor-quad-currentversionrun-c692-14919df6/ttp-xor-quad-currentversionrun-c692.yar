rule TTP_XOR_QUAD_CurrentVersionRun_c692 {
  strings:
    $key_c692 = { 95 fd [2] b1 f3 [2] 9a df [2] b4 fd [2] a0 e6 [2] af fc [2] b1 e1 [2] b3 e0 [2] a8 e6 [2] b4 e1 [2] a8 ce }

  condition:
    any of them
}