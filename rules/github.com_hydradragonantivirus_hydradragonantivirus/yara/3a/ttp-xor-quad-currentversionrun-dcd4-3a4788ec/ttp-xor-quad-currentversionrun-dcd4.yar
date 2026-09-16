rule TTP_XOR_QUAD_CurrentVersionRun_dcd4 {
  strings:
    $key_dcd4 = { 8f bb [2] ab b5 [2] 80 99 [2] ae bb [2] ba a0 [2] b5 ba [2] ab a7 [2] a9 a6 [2] b2 a0 [2] ae a7 [2] b2 88 }

  condition:
    any of them
}