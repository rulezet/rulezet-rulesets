rule TTP_XOR_QUAD_CurrentVersionRun_9391 {
  strings:
    $key_9391 = { c0 fe [2] e4 f0 [2] cf dc [2] e1 fe [2] f5 e5 [2] fa ff [2] e4 e2 [2] e6 e3 [2] fd e5 [2] e1 e2 [2] fd cd }

  condition:
    any of them
}