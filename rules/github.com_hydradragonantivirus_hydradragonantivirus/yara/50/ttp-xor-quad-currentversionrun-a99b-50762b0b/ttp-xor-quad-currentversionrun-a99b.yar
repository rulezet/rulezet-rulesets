rule TTP_XOR_QUAD_CurrentVersionRun_a99b {
  strings:
    $key_a99b = { fa f4 [2] de fa [2] f5 d6 [2] db f4 [2] cf ef [2] c0 f5 [2] de e8 [2] dc e9 [2] c7 ef [2] db e8 [2] c7 c7 }

  condition:
    any of them
}