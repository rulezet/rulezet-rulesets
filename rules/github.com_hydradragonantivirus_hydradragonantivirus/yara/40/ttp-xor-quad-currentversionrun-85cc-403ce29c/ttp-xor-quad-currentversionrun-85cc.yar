rule TTP_XOR_QUAD_CurrentVersionRun_85cc {
  strings:
    $key_85cc = { d6 a3 [2] f2 ad [2] d9 81 [2] f7 a3 [2] e3 b8 [2] ec a2 [2] f2 bf [2] f0 be [2] eb b8 [2] f7 bf [2] eb 90 }

  condition:
    any of them
}