rule TTP_XOR_QUAD_CurrentVersionRun_5219 {
  strings:
    $key_5219 = { 01 76 [2] 25 78 [2] 0e 54 [2] 20 76 [2] 34 6d [2] 3b 77 [2] 25 6a [2] 27 6b [2] 3c 6d [2] 20 6a [2] 3c 45 }

  condition:
    any of them
}