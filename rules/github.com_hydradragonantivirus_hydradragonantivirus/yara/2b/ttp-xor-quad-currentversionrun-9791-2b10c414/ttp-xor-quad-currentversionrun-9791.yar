rule TTP_XOR_QUAD_CurrentVersionRun_9791 {
  strings:
    $key_9791 = { c4 fe [2] e0 f0 [2] cb dc [2] e5 fe [2] f1 e5 [2] fe ff [2] e0 e2 [2] e2 e3 [2] f9 e5 [2] e5 e2 [2] f9 cd }

  condition:
    any of them
}