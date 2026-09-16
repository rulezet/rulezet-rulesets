rule TTP_XOR_QUAD_CurrentVersionRun_9ada {
  strings:
    $key_9ada = { c9 b5 [2] ed bb [2] c6 97 [2] e8 b5 [2] fc ae [2] f3 b4 [2] ed a9 [2] ef a8 [2] f4 ae [2] e8 a9 [2] f4 86 }

  condition:
    any of them
}