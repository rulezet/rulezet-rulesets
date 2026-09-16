rule TTP_XOR_QUAD_CurrentVersionRun_9390 {
  strings:
    $key_9390 = { c0 ff [2] e4 f1 [2] cf dd [2] e1 ff [2] f5 e4 [2] fa fe [2] e4 e3 [2] e6 e2 [2] fd e4 [2] e1 e3 [2] fd cc }

  condition:
    any of them
}