rule TTP_XOR_QUAD_CurrentVersionRun_1654 {
  strings:
    $key_1654 = { 45 3b [2] 61 35 [2] 4a 19 [2] 64 3b [2] 70 20 [2] 7f 3a [2] 61 27 [2] 63 26 [2] 78 20 [2] 64 27 [2] 78 08 }

  condition:
    any of them
}