rule TTP_XOR_QUAD_CurrentVersionRun_9fcc {
  strings:
    $key_9fcc = { cc a3 [2] e8 ad [2] c3 81 [2] ed a3 [2] f9 b8 [2] f6 a2 [2] e8 bf [2] ea be [2] f1 b8 [2] ed bf [2] f1 90 }

  condition:
    any of them
}