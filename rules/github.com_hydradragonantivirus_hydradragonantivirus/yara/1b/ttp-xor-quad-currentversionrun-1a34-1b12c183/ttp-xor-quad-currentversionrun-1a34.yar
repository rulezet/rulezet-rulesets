rule TTP_XOR_QUAD_CurrentVersionRun_1a34 {
  strings:
    $key_1a34 = { 49 5b [2] 6d 55 [2] 46 79 [2] 68 5b [2] 7c 40 [2] 73 5a [2] 6d 47 [2] 6f 46 [2] 74 40 [2] 68 47 [2] 74 68 }

  condition:
    any of them
}