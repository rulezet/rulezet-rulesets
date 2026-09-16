rule TTP_XOR_QUAD_CurrentVersionRun_84cc {
  strings:
    $key_84cc = { d7 a3 [2] f3 ad [2] d8 81 [2] f6 a3 [2] e2 b8 [2] ed a2 [2] f3 bf [2] f1 be [2] ea b8 [2] f6 bf [2] ea 90 }

  condition:
    any of them
}