rule TTP_XOR_QUAD_CurrentVersionRun_6617 {
  strings:
    $key_6617 = { 35 78 [2] 11 76 [2] 3a 5a [2] 14 78 [2] 00 63 [2] 0f 79 [2] 11 64 [2] 13 65 [2] 08 63 [2] 14 64 [2] 08 4b }

  condition:
    any of them
}