rule TTP_XOR_QUAD_CurrentVersionRun_93f7 {
  strings:
    $key_93f7 = { c0 98 [2] e4 96 [2] cf ba [2] e1 98 [2] f5 83 [2] fa 99 [2] e4 84 [2] e6 85 [2] fd 83 [2] e1 84 [2] fd ab }

  condition:
    any of them
}