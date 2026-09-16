rule TTP_XOR_QUAD_CurrentVersionRun_7639 {
  strings:
    $key_7639 = { 25 56 [2] 01 58 [2] 2a 74 [2] 04 56 [2] 10 4d [2] 1f 57 [2] 01 4a [2] 03 4b [2] 18 4d [2] 04 4a [2] 18 65 }

  condition:
    any of them
}