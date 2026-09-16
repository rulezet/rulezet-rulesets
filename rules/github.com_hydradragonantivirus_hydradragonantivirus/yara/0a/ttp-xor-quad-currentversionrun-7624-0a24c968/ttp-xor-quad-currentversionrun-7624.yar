rule TTP_XOR_QUAD_CurrentVersionRun_7624 {
  strings:
    $key_7624 = { 25 4b [2] 01 45 [2] 2a 69 [2] 04 4b [2] 10 50 [2] 1f 4a [2] 01 57 [2] 03 56 [2] 18 50 [2] 04 57 [2] 18 78 }

  condition:
    any of them
}