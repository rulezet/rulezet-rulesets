rule TTP_XOR_QUAD_CurrentVersionRun_8bb9 {
  strings:
    $key_8bb9 = { d8 d6 [2] fc d8 [2] d7 f4 [2] f9 d6 [2] ed cd [2] e2 d7 [2] fc ca [2] fe cb [2] e5 cd [2] f9 ca [2] e5 e5 }

  condition:
    any of them
}