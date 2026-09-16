rule TTP_XOR_QUAD_CurrentVersionRun_8497 {
  strings:
    $key_8497 = { d7 f8 [2] f3 f6 [2] d8 da [2] f6 f8 [2] e2 e3 [2] ed f9 [2] f3 e4 [2] f1 e5 [2] ea e3 [2] f6 e4 [2] ea cb }

  condition:
    any of them
}