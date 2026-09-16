rule TTP_XOR_QUAD_CurrentVersionRun_87ee {
  strings:
    $key_87ee = { d4 81 [2] f0 8f [2] db a3 [2] f5 81 [2] e1 9a [2] ee 80 [2] f0 9d [2] f2 9c [2] e9 9a [2] f5 9d [2] e9 b2 }

  condition:
    any of them
}