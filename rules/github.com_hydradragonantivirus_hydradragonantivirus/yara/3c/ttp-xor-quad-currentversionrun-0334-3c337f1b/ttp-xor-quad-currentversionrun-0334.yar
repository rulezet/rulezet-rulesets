rule TTP_XOR_QUAD_CurrentVersionRun_0334 {
  strings:
    $key_0334 = { 50 5b [2] 74 55 [2] 5f 79 [2] 71 5b [2] 65 40 [2] 6a 5a [2] 74 47 [2] 76 46 [2] 6d 40 [2] 71 47 [2] 6d 68 }

  condition:
    any of them
}