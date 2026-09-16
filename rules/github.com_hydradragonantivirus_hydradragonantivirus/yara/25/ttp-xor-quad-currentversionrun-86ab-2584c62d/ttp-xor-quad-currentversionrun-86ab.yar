rule TTP_XOR_QUAD_CurrentVersionRun_86ab {
  strings:
    $key_86ab = { d5 c4 [2] f1 ca [2] da e6 [2] f4 c4 [2] e0 df [2] ef c5 [2] f1 d8 [2] f3 d9 [2] e8 df [2] f4 d8 [2] e8 f7 }

  condition:
    any of them
}