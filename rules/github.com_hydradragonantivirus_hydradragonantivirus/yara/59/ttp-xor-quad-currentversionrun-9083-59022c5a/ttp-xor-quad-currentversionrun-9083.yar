rule TTP_XOR_QUAD_CurrentVersionRun_9083 {
  strings:
    $key_9083 = { c3 ec [2] e7 e2 [2] cc ce [2] e2 ec [2] f6 f7 [2] f9 ed [2] e7 f0 [2] e5 f1 [2] fe f7 [2] e2 f0 [2] fe df }

  condition:
    any of them
}