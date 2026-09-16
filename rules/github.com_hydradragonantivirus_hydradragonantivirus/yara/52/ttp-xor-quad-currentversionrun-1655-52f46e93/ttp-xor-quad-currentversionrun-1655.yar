rule TTP_XOR_QUAD_CurrentVersionRun_1655 {
  strings:
    $key_1655 = { 45 3a [2] 61 34 [2] 4a 18 [2] 64 3a [2] 70 21 [2] 7f 3b [2] 61 26 [2] 63 27 [2] 78 21 [2] 64 26 [2] 78 09 }

  condition:
    any of them
}