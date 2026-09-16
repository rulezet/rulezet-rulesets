rule TTP_XOR_QUAD_CurrentVersionRun_9a87 {
  strings:
    $key_9a87 = { c9 e8 [2] ed e6 [2] c6 ca [2] e8 e8 [2] fc f3 [2] f3 e9 [2] ed f4 [2] ef f5 [2] f4 f3 [2] e8 f4 [2] f4 db }

  condition:
    any of them
}