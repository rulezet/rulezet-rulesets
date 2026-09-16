rule TTP_XOR_QUAD_CurrentVersionRun_9082 {
  strings:
    $key_9082 = { c3 ed [2] e7 e3 [2] cc cf [2] e2 ed [2] f6 f6 [2] f9 ec [2] e7 f1 [2] e5 f0 [2] fe f6 [2] e2 f1 [2] fe de }

  condition:
    any of them
}