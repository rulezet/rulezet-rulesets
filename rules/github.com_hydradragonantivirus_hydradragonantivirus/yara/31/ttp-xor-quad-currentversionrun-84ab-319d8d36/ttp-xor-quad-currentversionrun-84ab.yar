rule TTP_XOR_QUAD_CurrentVersionRun_84ab {
  strings:
    $key_84ab = { d7 c4 [2] f3 ca [2] d8 e6 [2] f6 c4 [2] e2 df [2] ed c5 [2] f3 d8 [2] f1 d9 [2] ea df [2] f6 d8 [2] ea f7 }

  condition:
    any of them
}