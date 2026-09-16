rule TTP_XOR_QUAD_CurrentVersionRun_9315 {
  strings:
    $key_9315 = { c0 7a [2] e4 74 [2] cf 58 [2] e1 7a [2] f5 61 [2] fa 7b [2] e4 66 [2] e6 67 [2] fd 61 [2] e1 66 [2] fd 49 }

  condition:
    any of them
}