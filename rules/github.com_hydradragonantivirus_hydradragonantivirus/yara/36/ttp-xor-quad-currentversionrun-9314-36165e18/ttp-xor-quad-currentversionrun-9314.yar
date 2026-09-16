rule TTP_XOR_QUAD_CurrentVersionRun_9314 {
  strings:
    $key_9314 = { c0 7b [2] e4 75 [2] cf 59 [2] e1 7b [2] f5 60 [2] fa 7a [2] e4 67 [2] e6 66 [2] fd 60 [2] e1 67 [2] fd 48 }

  condition:
    any of them
}