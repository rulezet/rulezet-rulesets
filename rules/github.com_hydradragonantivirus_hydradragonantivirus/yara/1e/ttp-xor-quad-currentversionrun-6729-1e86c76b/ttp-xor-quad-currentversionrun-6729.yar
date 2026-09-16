rule TTP_XOR_QUAD_CurrentVersionRun_6729 {
  strings:
    $key_6729 = { 34 46 [2] 10 48 [2] 3b 64 [2] 15 46 [2] 01 5d [2] 0e 47 [2] 10 5a [2] 12 5b [2] 09 5d [2] 15 5a [2] 09 75 }

  condition:
    any of them
}