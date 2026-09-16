rule TTP_XOR_QUAD_CurrentVersionRun_bfdf {
  strings:
    $key_bfdf = { ec b0 [2] c8 be [2] e3 92 [2] cd b0 [2] d9 ab [2] d6 b1 [2] c8 ac [2] ca ad [2] d1 ab [2] cd ac [2] d1 83 }

  condition:
    any of them
}