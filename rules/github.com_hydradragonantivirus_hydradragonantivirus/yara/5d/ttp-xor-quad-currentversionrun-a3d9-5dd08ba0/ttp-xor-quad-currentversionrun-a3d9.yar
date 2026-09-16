rule TTP_XOR_QUAD_CurrentVersionRun_a3d9 {
  strings:
    $key_a3d9 = { f0 b6 [2] d4 b8 [2] ff 94 [2] d1 b6 [2] c5 ad [2] ca b7 [2] d4 aa [2] d6 ab [2] cd ad [2] d1 aa [2] cd 85 }

  condition:
    any of them
}