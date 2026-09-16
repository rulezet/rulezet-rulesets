rule TTP_XOR_QUAD_CurrentVersionRun_97e3 {
  strings:
    $key_97e3 = { c4 8c [2] e0 82 [2] cb ae [2] e5 8c [2] f1 97 [2] fe 8d [2] e0 90 [2] e2 91 [2] f9 97 [2] e5 90 [2] f9 bf }

  condition:
    any of them
}