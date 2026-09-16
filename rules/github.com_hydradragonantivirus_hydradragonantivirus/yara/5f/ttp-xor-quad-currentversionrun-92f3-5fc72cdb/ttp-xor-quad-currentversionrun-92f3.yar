rule TTP_XOR_QUAD_CurrentVersionRun_92f3 {
  strings:
    $key_92f3 = { c1 9c [2] e5 92 [2] ce be [2] e0 9c [2] f4 87 [2] fb 9d [2] e5 80 [2] e7 81 [2] fc 87 [2] e0 80 [2] fc af }

  condition:
    any of them
}