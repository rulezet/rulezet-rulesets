rule TTP_XOR_QUAD_CurrentVersionRun_7608 {
  strings:
    $key_7608 = { 25 67 [2] 01 69 [2] 2a 45 [2] 04 67 [2] 10 7c [2] 1f 66 [2] 01 7b [2] 03 7a [2] 18 7c [2] 04 7b [2] 18 54 }

  condition:
    any of them
}