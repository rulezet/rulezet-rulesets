rule TTP_XOR_QUAD_CurrentVersionRun_9796 {
  strings:
    $key_9796 = { c4 f9 [2] e0 f7 [2] cb db [2] e5 f9 [2] f1 e2 [2] fe f8 [2] e0 e5 [2] e2 e4 [2] f9 e2 [2] e5 e5 [2] f9 ca }

  condition:
    any of them
}