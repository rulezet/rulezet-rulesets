rule TTP_XOR_QUAD_CurrentVersionRun_a988 {
  strings:
    $key_a988 = { fa e7 [2] de e9 [2] f5 c5 [2] db e7 [2] cf fc [2] c0 e6 [2] de fb [2] dc fa [2] c7 fc [2] db fb [2] c7 d4 }

  condition:
    any of them
}