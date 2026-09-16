rule TTP_XOR_QUAD_CurrentVersionRun_1f28 {
  strings:
    $key_1f28 = { 4c 47 [2] 68 49 [2] 43 65 [2] 6d 47 [2] 79 5c [2] 76 46 [2] 68 5b [2] 6a 5a [2] 71 5c [2] 6d 5b [2] 71 74 }

  condition:
    any of them
}