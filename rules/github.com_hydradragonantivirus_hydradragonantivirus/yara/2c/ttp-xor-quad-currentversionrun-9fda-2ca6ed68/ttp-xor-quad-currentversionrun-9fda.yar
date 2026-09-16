rule TTP_XOR_QUAD_CurrentVersionRun_9fda {
  strings:
    $key_9fda = { cc b5 [2] e8 bb [2] c3 97 [2] ed b5 [2] f9 ae [2] f6 b4 [2] e8 a9 [2] ea a8 [2] f1 ae [2] ed a9 [2] f1 86 }

  condition:
    any of them
}