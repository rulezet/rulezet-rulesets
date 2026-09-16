rule TTP_XOR_QUAD_CurrentVersionRun_7665 {
  strings:
    $key_7665 = { 25 0a [2] 01 04 [2] 2a 28 [2] 04 0a [2] 10 11 [2] 1f 0b [2] 01 16 [2] 03 17 [2] 18 11 [2] 04 16 [2] 18 39 }

  condition:
    any of them
}