rule TTP_XOR_QUAD_CurrentVersionRun_9338 {
  strings:
    $key_9338 = { c0 57 [2] e4 59 [2] cf 75 [2] e1 57 [2] f5 4c [2] fa 56 [2] e4 4b [2] e6 4a [2] fd 4c [2] e1 4b [2] fd 64 }

  condition:
    any of them
}