rule TTP_XOR_QUAD_CurrentVersionRun_97cc {
  strings:
    $key_97cc = { c4 a3 [2] e0 ad [2] cb 81 [2] e5 a3 [2] f1 b8 [2] fe a2 [2] e0 bf [2] e2 be [2] f9 b8 [2] e5 bf [2] f9 90 }

  condition:
    any of them
}