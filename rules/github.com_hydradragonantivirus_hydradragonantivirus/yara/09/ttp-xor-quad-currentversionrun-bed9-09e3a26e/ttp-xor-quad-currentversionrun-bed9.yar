rule TTP_XOR_QUAD_CurrentVersionRun_bed9 {
  strings:
    $key_bed9 = { ed b6 [2] c9 b8 [2] e2 94 [2] cc b6 [2] d8 ad [2] d7 b7 [2] c9 aa [2] cb ab [2] d0 ad [2] cc aa [2] d0 85 }

  condition:
    any of them
}