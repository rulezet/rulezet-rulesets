rule TTP_XOR_QUAD_CurrentVersionRun_98b9 {
  strings:
    $key_98b9 = { cb d6 [2] ef d8 [2] c4 f4 [2] ea d6 [2] fe cd [2] f1 d7 [2] ef ca [2] ed cb [2] f6 cd [2] ea ca [2] f6 e5 }

  condition:
    any of them
}