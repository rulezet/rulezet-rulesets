rule TTP_XOR_QUAD_CurrentVersionRun_c592 {
  strings:
    $key_c592 = { 96 fd [2] b2 f3 [2] 99 df [2] b7 fd [2] a3 e6 [2] ac fc [2] b2 e1 [2] b0 e0 [2] ab e6 [2] b7 e1 [2] ab ce }

  condition:
    any of them
}