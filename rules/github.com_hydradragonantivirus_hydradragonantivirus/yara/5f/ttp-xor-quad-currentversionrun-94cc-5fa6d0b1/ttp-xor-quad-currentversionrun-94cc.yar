rule TTP_XOR_QUAD_CurrentVersionRun_94cc {
  strings:
    $key_94cc = { c7 a3 [2] e3 ad [2] c8 81 [2] e6 a3 [2] f2 b8 [2] fd a2 [2] e3 bf [2] e1 be [2] fa b8 [2] e6 bf [2] fa 90 }

  condition:
    any of them
}