rule TTP_XOR_QUAD_CurrentVersionRun_866d {
  strings:
    $key_866d = { d5 02 [2] f1 0c [2] da 20 [2] f4 02 [2] e0 19 [2] ef 03 [2] f1 1e [2] f3 1f [2] e8 19 [2] f4 1e [2] e8 31 }

  condition:
    any of them
}