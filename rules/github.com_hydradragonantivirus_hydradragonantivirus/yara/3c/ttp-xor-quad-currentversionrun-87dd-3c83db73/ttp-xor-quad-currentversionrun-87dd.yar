rule TTP_XOR_QUAD_CurrentVersionRun_87dd {
  strings:
    $key_87dd = { d4 b2 [2] f0 bc [2] db 90 [2] f5 b2 [2] e1 a9 [2] ee b3 [2] f0 ae [2] f2 af [2] e9 a9 [2] f5 ae [2] e9 81 }

  condition:
    any of them
}