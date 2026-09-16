rule TTP_XOR_QUAD_CurrentVersionRun_4c35 {
  strings:
    $key_4c35 = { 1f 5a [2] 3b 54 [2] 10 78 [2] 3e 5a [2] 2a 41 [2] 25 5b [2] 3b 46 [2] 39 47 [2] 22 41 [2] 3e 46 [2] 22 69 }

  condition:
    any of them
}