rule TTP_XOR_QUAD_CurrentVersionRun_6828 {
  strings:
    $key_6828 = { 3b 47 [2] 1f 49 [2] 34 65 [2] 1a 47 [2] 0e 5c [2] 01 46 [2] 1f 5b [2] 1d 5a [2] 06 5c [2] 1a 5b [2] 06 74 }

  condition:
    any of them
}