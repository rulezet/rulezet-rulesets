rule TTP_XOR_QUAD_CurrentVersionRun_4c28 {
  strings:
    $key_4c28 = { 1f 47 [2] 3b 49 [2] 10 65 [2] 3e 47 [2] 2a 5c [2] 25 46 [2] 3b 5b [2] 39 5a [2] 22 5c [2] 3e 5b [2] 22 74 }

  condition:
    any of them
}