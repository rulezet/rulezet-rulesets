rule TTP_XOR_QUAD_CurrentVersionRun_91f3 {
  strings:
    $key_91f3 = { c2 9c [2] e6 92 [2] cd be [2] e3 9c [2] f7 87 [2] f8 9d [2] e6 80 [2] e4 81 [2] ff 87 [2] e3 80 [2] ff af }

  condition:
    any of them
}