rule TTP_XOR_QUAD_CurrentVersionRun_9364 {
  strings:
    $key_9364 = { c0 0b [2] e4 05 [2] cf 29 [2] e1 0b [2] f5 10 [2] fa 0a [2] e4 17 [2] e6 16 [2] fd 10 [2] e1 17 [2] fd 38 }

  condition:
    any of them
}