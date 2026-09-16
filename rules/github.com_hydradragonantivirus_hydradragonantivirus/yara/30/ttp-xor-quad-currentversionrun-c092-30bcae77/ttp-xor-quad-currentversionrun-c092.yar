rule TTP_XOR_QUAD_CurrentVersionRun_c092 {
  strings:
    $key_c092 = { 93 fd [2] b7 f3 [2] 9c df [2] b2 fd [2] a6 e6 [2] a9 fc [2] b7 e1 [2] b5 e0 [2] ae e6 [2] b2 e1 [2] ae ce }

  condition:
    any of them
}