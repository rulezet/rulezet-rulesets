rule TTP_XOR_QUAD_CurrentVersionRun_7328 {
  strings:
    $key_7328 = { 20 47 [2] 04 49 [2] 2f 65 [2] 01 47 [2] 15 5c [2] 1a 46 [2] 04 5b [2] 06 5a [2] 1d 5c [2] 01 5b [2] 1d 74 }

  condition:
    any of them
}