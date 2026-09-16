rule TTP_XOR_QUAD_CurrentVersionRun_9db9 {
  strings:
    $key_9db9 = { ce d6 [2] ea d8 [2] c1 f4 [2] ef d6 [2] fb cd [2] f4 d7 [2] ea ca [2] e8 cb [2] f3 cd [2] ef ca [2] f3 e5 }

  condition:
    any of them
}