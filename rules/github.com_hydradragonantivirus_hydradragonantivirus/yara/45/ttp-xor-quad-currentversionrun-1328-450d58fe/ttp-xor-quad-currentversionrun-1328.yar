rule TTP_XOR_QUAD_CurrentVersionRun_1328 {
  strings:
    $key_1328 = { 40 47 [2] 64 49 [2] 4f 65 [2] 61 47 [2] 75 5c [2] 7a 46 [2] 64 5b [2] 66 5a [2] 7d 5c [2] 61 5b [2] 7d 74 }

  condition:
    any of them
}