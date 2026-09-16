rule TTP_XOR_QUAD_CurrentVersionRun_7c28 {
  strings:
    $key_7c28 = { 2f 47 [2] 0b 49 [2] 20 65 [2] 0e 47 [2] 1a 5c [2] 15 46 [2] 0b 5b [2] 09 5a [2] 12 5c [2] 0e 5b [2] 12 74 }

  condition:
    any of them
}