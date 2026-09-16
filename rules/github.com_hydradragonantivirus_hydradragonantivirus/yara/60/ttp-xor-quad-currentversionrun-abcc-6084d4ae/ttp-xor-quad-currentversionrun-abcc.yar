rule TTP_XOR_QUAD_CurrentVersionRun_abcc {
  strings:
    $key_abcc = { f8 a3 [2] dc ad [2] f7 81 [2] d9 a3 [2] cd b8 [2] c2 a2 [2] dc bf [2] de be [2] c5 b8 [2] d9 bf [2] c5 90 }

  condition:
    any of them
}