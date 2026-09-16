rule TTP_XOR_QUAD_CurrentVersionRun_bad9 {
  strings:
    $key_bad9 = { e9 b6 [2] cd b8 [2] e6 94 [2] c8 b6 [2] dc ad [2] d3 b7 [2] cd aa [2] cf ab [2] d4 ad [2] c8 aa [2] d4 85 }

  condition:
    any of them
}