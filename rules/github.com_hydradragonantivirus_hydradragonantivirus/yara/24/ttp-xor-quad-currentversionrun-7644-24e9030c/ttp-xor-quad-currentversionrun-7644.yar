rule TTP_XOR_QUAD_CurrentVersionRun_7644 {
  strings:
    $key_7644 = { 25 2b [2] 01 25 [2] 2a 09 [2] 04 2b [2] 10 30 [2] 1f 2a [2] 01 37 [2] 03 36 [2] 18 30 [2] 04 37 [2] 18 18 }

  condition:
    any of them
}