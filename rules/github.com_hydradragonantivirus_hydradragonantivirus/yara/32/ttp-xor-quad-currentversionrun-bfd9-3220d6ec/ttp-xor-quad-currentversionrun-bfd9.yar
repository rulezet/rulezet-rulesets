rule TTP_XOR_QUAD_CurrentVersionRun_bfd9 {
  strings:
    $key_bfd9 = { ec b6 [2] c8 b8 [2] e3 94 [2] cd b6 [2] d9 ad [2] d6 b7 [2] c8 aa [2] ca ab [2] d1 ad [2] cd aa [2] d1 85 }

  condition:
    any of them
}