rule TTP_XOR_QUAD_CurrentVersionRun_94e0 {
  strings:
    $key_94e0 = { c7 8f [2] e3 81 [2] c8 ad [2] e6 8f [2] f2 94 [2] fd 8e [2] e3 93 [2] e1 92 [2] fa 94 [2] e6 93 [2] fa bc }

  condition:
    any of them
}