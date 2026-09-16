rule TTP_XOR_QUAD_CurrentVersionRun_6624 {
  strings:
    $key_6624 = { 35 4b [2] 11 45 [2] 3a 69 [2] 14 4b [2] 00 50 [2] 0f 4a [2] 11 57 [2] 13 56 [2] 08 50 [2] 14 57 [2] 08 78 }

  condition:
    any of them
}