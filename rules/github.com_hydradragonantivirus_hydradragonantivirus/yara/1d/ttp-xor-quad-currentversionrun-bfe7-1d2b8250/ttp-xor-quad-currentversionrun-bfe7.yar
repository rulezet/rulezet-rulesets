rule TTP_XOR_QUAD_CurrentVersionRun_bfe7 {
  strings:
    $key_bfe7 = { ec 88 [2] c8 86 [2] e3 aa [2] cd 88 [2] d9 93 [2] d6 89 [2] c8 94 [2] ca 95 [2] d1 93 [2] cd 94 [2] d1 bb }

  condition:
    any of them
}