rule TTP_XOR_QUAD_CurrentVersionRun_97fe {
  strings:
    $key_97fe = { c4 91 [2] e0 9f [2] cb b3 [2] e5 91 [2] f1 8a [2] fe 90 [2] e0 8d [2] e2 8c [2] f9 8a [2] e5 8d [2] f9 a2 }

  condition:
    any of them
}