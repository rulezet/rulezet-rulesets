rule TTP_XOR_QUAD_CurrentVersionRun_4c34 {
  strings:
    $key_4c34 = { 1f 5b [2] 3b 55 [2] 10 79 [2] 3e 5b [2] 2a 40 [2] 25 5a [2] 3b 47 [2] 39 46 [2] 22 40 [2] 3e 47 [2] 22 68 }

  condition:
    any of them
}