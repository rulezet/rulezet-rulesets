rule TTP_XOR_QUAD_CurrentVersionRun_0a55 {
  strings:
    $key_0a55 = { 59 3a [2] 7d 34 [2] 56 18 [2] 78 3a [2] 6c 21 [2] 63 3b [2] 7d 26 [2] 7f 27 [2] 64 21 [2] 78 26 [2] 64 09 }

  condition:
    any of them
}