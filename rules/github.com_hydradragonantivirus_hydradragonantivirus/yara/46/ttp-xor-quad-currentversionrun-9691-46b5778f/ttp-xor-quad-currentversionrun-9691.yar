rule TTP_XOR_QUAD_CurrentVersionRun_9691 {
  strings:
    $key_9691 = { c5 fe [2] e1 f0 [2] ca dc [2] e4 fe [2] f0 e5 [2] ff ff [2] e1 e2 [2] e3 e3 [2] f8 e5 [2] e4 e2 [2] f8 cd }

  condition:
    any of them
}