rule TTP_XOR_QUAD_CurrentVersionRun_9685 {
  strings:
    $key_9685 = { c5 ea [2] e1 e4 [2] ca c8 [2] e4 ea [2] f0 f1 [2] ff eb [2] e1 f6 [2] e3 f7 [2] f8 f1 [2] e4 f6 [2] f8 d9 }

  condition:
    any of them
}