rule TTP_XOR_QUAD_CurrentVersionRun_96ee {
  strings:
    $key_96ee = { c5 81 [2] e1 8f [2] ca a3 [2] e4 81 [2] f0 9a [2] ff 80 [2] e1 9d [2] e3 9c [2] f8 9a [2] e4 9d [2] f8 b2 }

  condition:
    any of them
}