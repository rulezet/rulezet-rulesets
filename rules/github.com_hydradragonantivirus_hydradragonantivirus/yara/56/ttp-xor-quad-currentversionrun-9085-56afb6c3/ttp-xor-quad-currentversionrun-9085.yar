rule TTP_XOR_QUAD_CurrentVersionRun_9085 {
  strings:
    $key_9085 = { c3 ea [2] e7 e4 [2] cc c8 [2] e2 ea [2] f6 f1 [2] f9 eb [2] e7 f6 [2] e5 f7 [2] fe f1 [2] e2 f6 [2] fe d9 }

  condition:
    any of them
}