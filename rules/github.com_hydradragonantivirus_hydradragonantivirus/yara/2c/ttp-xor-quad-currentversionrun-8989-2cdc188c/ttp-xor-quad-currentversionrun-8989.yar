rule TTP_XOR_QUAD_CurrentVersionRun_8989 {
  strings:
    $key_8989 = { da e6 [2] fe e8 [2] d5 c4 [2] fb e6 [2] ef fd [2] e0 e7 [2] fe fa [2] fc fb [2] e7 fd [2] fb fa [2] e7 d5 }

  condition:
    any of them
}