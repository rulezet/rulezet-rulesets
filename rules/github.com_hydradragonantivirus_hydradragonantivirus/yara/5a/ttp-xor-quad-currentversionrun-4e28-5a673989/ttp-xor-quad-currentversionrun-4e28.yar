rule TTP_XOR_QUAD_CurrentVersionRun_4e28 {
  strings:
    $key_4e28 = { 1d 47 [2] 39 49 [2] 12 65 [2] 3c 47 [2] 28 5c [2] 27 46 [2] 39 5b [2] 3b 5a [2] 20 5c [2] 3c 5b [2] 20 74 }

  condition:
    any of them
}