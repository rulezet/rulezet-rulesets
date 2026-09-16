rule TTP_XOR_QUAD_CurrentVersionRun_9fbf {
  strings:
    $key_9fbf = { cc d0 [2] e8 de [2] c3 f2 [2] ed d0 [2] f9 cb [2] f6 d1 [2] e8 cc [2] ea cd [2] f1 cb [2] ed cc [2] f1 e3 }

  condition:
    any of them
}