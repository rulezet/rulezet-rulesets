rule TTP_XOR_QUAD_CurrentVersionRun_2234 {
  strings:
    $key_2234 = { 71 5b [2] 55 55 [2] 7e 79 [2] 50 5b [2] 44 40 [2] 4b 5a [2] 55 47 [2] 57 46 [2] 4c 40 [2] 50 47 [2] 4c 68 }

  condition:
    any of them
}