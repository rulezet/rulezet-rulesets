rule TTP_XOR_QUAD_CurrentVersionRun_bfd8 {
  strings:
    $key_bfd8 = { ec b7 [2] c8 b9 [2] e3 95 [2] cd b7 [2] d9 ac [2] d6 b6 [2] c8 ab [2] ca aa [2] d1 ac [2] cd ab [2] d1 84 }

  condition:
    any of them
}