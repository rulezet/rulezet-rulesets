rule TTP_XOR_QUAD_CurrentVersionRun_94f6 {
  strings:
    $key_94f6 = { c7 99 [2] e3 97 [2] c8 bb [2] e6 99 [2] f2 82 [2] fd 98 [2] e3 85 [2] e1 84 [2] fa 82 [2] e6 85 [2] fa aa }

  condition:
    any of them
}