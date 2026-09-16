rule TTP_XOR_QUAD_CurrentVersionRun_bacc {
  strings:
    $key_bacc = { e9 a3 [2] cd ad [2] e6 81 [2] c8 a3 [2] dc b8 [2] d3 a2 [2] cd bf [2] cf be [2] d4 b8 [2] c8 bf [2] d4 90 }

  condition:
    any of them
}