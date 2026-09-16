rule TTP_XOR_QUAD_CurrentVersionRun_8b88 {
  strings:
    $key_8b88 = { d8 e7 [2] fc e9 [2] d7 c5 [2] f9 e7 [2] ed fc [2] e2 e6 [2] fc fb [2] fe fa [2] e5 fc [2] f9 fb [2] e5 d4 }

  condition:
    any of them
}