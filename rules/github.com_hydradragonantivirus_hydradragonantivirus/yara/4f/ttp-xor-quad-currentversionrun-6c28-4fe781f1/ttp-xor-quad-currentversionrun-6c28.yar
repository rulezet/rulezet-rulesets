rule TTP_XOR_QUAD_CurrentVersionRun_6c28 {
  strings:
    $key_6c28 = { 3f 47 [2] 1b 49 [2] 30 65 [2] 1e 47 [2] 0a 5c [2] 05 46 [2] 1b 5b [2] 19 5a [2] 02 5c [2] 1e 5b [2] 02 74 }

  condition:
    any of them
}