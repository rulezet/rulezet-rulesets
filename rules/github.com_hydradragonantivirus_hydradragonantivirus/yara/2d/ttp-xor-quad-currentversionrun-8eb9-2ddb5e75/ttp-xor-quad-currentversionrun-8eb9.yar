rule TTP_XOR_QUAD_CurrentVersionRun_8eb9 {
  strings:
    $key_8eb9 = { dd d6 [2] f9 d8 [2] d2 f4 [2] fc d6 [2] e8 cd [2] e7 d7 [2] f9 ca [2] fb cb [2] e0 cd [2] fc ca [2] e0 e5 }

  condition:
    any of them
}