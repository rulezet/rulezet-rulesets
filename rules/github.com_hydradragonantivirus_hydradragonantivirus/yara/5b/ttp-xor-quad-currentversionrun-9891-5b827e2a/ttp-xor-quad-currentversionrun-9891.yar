rule TTP_XOR_QUAD_CurrentVersionRun_9891 {
  strings:
    $key_9891 = { cb fe [2] ef f0 [2] c4 dc [2] ea fe [2] fe e5 [2] f1 ff [2] ef e2 [2] ed e3 [2] f6 e5 [2] ea e2 [2] f6 cd }

  condition:
    any of them
}