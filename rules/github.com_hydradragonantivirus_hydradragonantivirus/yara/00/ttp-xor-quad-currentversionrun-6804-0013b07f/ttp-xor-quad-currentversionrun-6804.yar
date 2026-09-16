rule TTP_XOR_QUAD_CurrentVersionRun_6804 {
  strings:
    $key_6804 = { 3b 6b [2] 1f 65 [2] 34 49 [2] 1a 6b [2] 0e 70 [2] 01 6a [2] 1f 77 [2] 1d 76 [2] 06 70 [2] 1a 77 [2] 06 58 }

  condition:
    any of them
}