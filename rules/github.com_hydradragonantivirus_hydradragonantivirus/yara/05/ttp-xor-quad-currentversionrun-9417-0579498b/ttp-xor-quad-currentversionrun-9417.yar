rule TTP_XOR_QUAD_CurrentVersionRun_9417 {
  strings:
    $key_9417 = { c7 78 [2] e3 76 [2] c8 5a [2] e6 78 [2] f2 63 [2] fd 79 [2] e3 64 [2] e1 65 [2] fa 63 [2] e6 64 [2] fa 4b }

  condition:
    any of them
}