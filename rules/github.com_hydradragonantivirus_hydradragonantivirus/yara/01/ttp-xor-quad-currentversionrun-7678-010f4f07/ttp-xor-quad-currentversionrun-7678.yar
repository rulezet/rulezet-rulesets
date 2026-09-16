rule TTP_XOR_QUAD_CurrentVersionRun_7678 {
  strings:
    $key_7678 = { 25 17 [2] 01 19 [2] 2a 35 [2] 04 17 [2] 10 0c [2] 1f 16 [2] 01 0b [2] 03 0a [2] 18 0c [2] 04 0b [2] 18 24 }

  condition:
    any of them
}