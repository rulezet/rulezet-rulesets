rule TTP_XOR_QUAD_CurrentVersionRun_4c79 {
  strings:
    $key_4c79 = { 1f 16 [2] 3b 18 [2] 10 34 [2] 3e 16 [2] 2a 0d [2] 25 17 [2] 3b 0a [2] 39 0b [2] 22 0d [2] 3e 0a [2] 22 25 }

  condition:
    any of them
}