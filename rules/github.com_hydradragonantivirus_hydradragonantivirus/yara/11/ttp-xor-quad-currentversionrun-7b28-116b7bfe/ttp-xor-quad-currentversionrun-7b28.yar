rule TTP_XOR_QUAD_CurrentVersionRun_7b28 {
  strings:
    $key_7b28 = { 28 47 [2] 0c 49 [2] 27 65 [2] 09 47 [2] 1d 5c [2] 12 46 [2] 0c 5b [2] 0e 5a [2] 15 5c [2] 09 5b [2] 15 74 }

  condition:
    any of them
}