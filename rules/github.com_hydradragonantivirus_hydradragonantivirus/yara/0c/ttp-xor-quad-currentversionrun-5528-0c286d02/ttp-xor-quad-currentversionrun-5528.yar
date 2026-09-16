rule TTP_XOR_QUAD_CurrentVersionRun_5528 {
  strings:
    $key_5528 = { 06 47 [2] 22 49 [2] 09 65 [2] 27 47 [2] 33 5c [2] 3c 46 [2] 22 5b [2] 20 5a [2] 3b 5c [2] 27 5b [2] 3b 74 }

  condition:
    any of them
}