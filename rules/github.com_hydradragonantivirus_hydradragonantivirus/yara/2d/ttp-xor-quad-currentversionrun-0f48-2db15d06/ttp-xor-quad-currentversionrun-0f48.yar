rule TTP_XOR_QUAD_CurrentVersionRun_0f48 {
  strings:
    $key_0f48 = { 5c 27 [2] 78 29 [2] 53 05 [2] 7d 27 [2] 69 3c [2] 66 26 [2] 78 3b [2] 7a 3a [2] 61 3c [2] 7d 3b [2] 61 14 }

  condition:
    any of them
}