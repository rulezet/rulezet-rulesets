rule TTP_XOR_QUAD_CurrentVersionRun_a888 {
  strings:
    $key_a888 = { fb e7 [2] df e9 [2] f4 c5 [2] da e7 [2] ce fc [2] c1 e6 [2] df fb [2] dd fa [2] c6 fc [2] da fb [2] c6 d4 }

  condition:
    any of them
}