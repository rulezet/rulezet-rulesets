rule TTP_XOR_QUAD_CurrentVersionRun_94f7 {
  strings:
    $key_94f7 = { c7 98 [2] e3 96 [2] c8 ba [2] e6 98 [2] f2 83 [2] fd 99 [2] e3 84 [2] e1 85 [2] fa 83 [2] e6 84 [2] fa ab }

  condition:
    any of them
}