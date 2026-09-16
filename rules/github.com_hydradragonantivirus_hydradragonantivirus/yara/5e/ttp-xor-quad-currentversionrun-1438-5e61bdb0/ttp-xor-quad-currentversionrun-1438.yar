rule TTP_XOR_QUAD_CurrentVersionRun_1438 {
  strings:
    $key_1438 = { 47 57 [2] 63 59 [2] 48 75 [2] 66 57 [2] 72 4c [2] 7d 56 [2] 63 4b [2] 61 4a [2] 7a 4c [2] 66 4b [2] 7a 64 }

  condition:
    any of them
}