rule TTP_XOR_QUAD_CurrentVersionRun_baee {
  strings:
    $key_baee = { e9 81 [2] cd 8f [2] e6 a3 [2] c8 81 [2] dc 9a [2] d3 80 [2] cd 9d [2] cf 9c [2] d4 9a [2] c8 9d [2] d4 b2 }

  condition:
    any of them
}