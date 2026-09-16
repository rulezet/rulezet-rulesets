rule TTP_XOR_QUAD_CurrentVersionRun_8492 {
  strings:
    $key_8492 = { d7 fd [2] f3 f3 [2] d8 df [2] f6 fd [2] e2 e6 [2] ed fc [2] f3 e1 [2] f1 e0 [2] ea e6 [2] f6 e1 [2] ea ce }

  condition:
    any of them
}