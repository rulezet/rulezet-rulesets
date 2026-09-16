rule TTP_XOR_QUAD_CurrentVersionRun_bad8 {
  strings:
    $key_bad8 = { e9 b7 [2] cd b9 [2] e6 95 [2] c8 b7 [2] dc ac [2] d3 b6 [2] cd ab [2] cf aa [2] d4 ac [2] c8 ab [2] d4 84 }

  condition:
    any of them
}