rule TTP_XOR_QUAD_CurrentVersionRun_7679 {
  strings:
    $key_7679 = { 25 16 [2] 01 18 [2] 2a 34 [2] 04 16 [2] 10 0d [2] 1f 17 [2] 01 0a [2] 03 0b [2] 18 0d [2] 04 0a [2] 18 25 }

  condition:
    any of them
}