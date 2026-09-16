rule TTP_XOR_QUAD_CurrentVersionRun_7728 {
  strings:
    $key_7728 = { 24 47 [2] 00 49 [2] 2b 65 [2] 05 47 [2] 11 5c [2] 1e 46 [2] 00 5b [2] 02 5a [2] 19 5c [2] 05 5b [2] 19 74 }

  condition:
    any of them
}