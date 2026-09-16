rule TTP_XOR_QUAD_CurrentVersionRun_8687 {
  strings:
    $key_8687 = { d5 e8 [2] f1 e6 [2] da ca [2] f4 e8 [2] e0 f3 [2] ef e9 [2] f1 f4 [2] f3 f5 [2] e8 f3 [2] f4 f4 [2] e8 db }

  condition:
    any of them
}