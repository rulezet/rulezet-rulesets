rule TTP_XOR_QUAD_CurrentVersionRun_7648 {
  strings:
    $key_7648 = { 25 27 [2] 01 29 [2] 2a 05 [2] 04 27 [2] 10 3c [2] 1f 26 [2] 01 3b [2] 03 3a [2] 18 3c [2] 04 3b [2] 18 14 }

  condition:
    any of them
}