rule TTP_XOR_QUAD_CurrentVersionRun_7335 {
  strings:
    $key_7335 = { 20 5a [2] 04 54 [2] 2f 78 [2] 01 5a [2] 15 41 [2] 1a 5b [2] 04 46 [2] 06 47 [2] 1d 41 [2] 01 46 [2] 1d 69 }

  condition:
    any of them
}