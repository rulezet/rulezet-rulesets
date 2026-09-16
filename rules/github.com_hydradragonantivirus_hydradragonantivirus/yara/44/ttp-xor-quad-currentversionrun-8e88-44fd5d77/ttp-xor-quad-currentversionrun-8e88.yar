rule TTP_XOR_QUAD_CurrentVersionRun_8e88 {
  strings:
    $key_8e88 = { dd e7 [2] f9 e9 [2] d2 c5 [2] fc e7 [2] e8 fc [2] e7 e6 [2] f9 fb [2] fb fa [2] e0 fc [2] fc fb [2] e0 d4 }

  condition:
    any of them
}