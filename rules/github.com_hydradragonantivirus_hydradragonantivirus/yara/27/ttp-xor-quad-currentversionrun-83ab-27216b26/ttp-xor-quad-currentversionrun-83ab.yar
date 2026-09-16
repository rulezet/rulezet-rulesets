rule TTP_XOR_QUAD_CurrentVersionRun_83ab {
  strings:
    $key_83ab = { d0 c4 [2] f4 ca [2] df e6 [2] f1 c4 [2] e5 df [2] ea c5 [2] f4 d8 [2] f6 d9 [2] ed df [2] f1 d8 [2] ed f7 }

  condition:
    any of them
}