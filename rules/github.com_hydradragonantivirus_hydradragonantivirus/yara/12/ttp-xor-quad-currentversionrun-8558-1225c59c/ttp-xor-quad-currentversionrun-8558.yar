rule TTP_XOR_QUAD_CurrentVersionRun_8558 {
  strings:
    $key_8558 = { d6 37 [2] f2 39 [2] d9 15 [2] f7 37 [2] e3 2c [2] ec 36 [2] f2 2b [2] f0 2a [2] eb 2c [2] f7 2b [2] eb 04 }

  condition:
    any of them
}