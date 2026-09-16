rule TTP_XOR_QUAD_CurrentVersionRun_1649 {
  strings:
    $key_1649 = { 45 26 [2] 61 28 [2] 4a 04 [2] 64 26 [2] 70 3d [2] 7f 27 [2] 61 3a [2] 63 3b [2] 78 3d [2] 64 3a [2] 78 15 }

  condition:
    any of them
}