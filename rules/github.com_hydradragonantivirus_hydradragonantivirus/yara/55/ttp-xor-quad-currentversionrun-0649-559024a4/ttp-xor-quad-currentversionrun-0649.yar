rule TTP_XOR_QUAD_CurrentVersionRun_0649 {
  strings:
    $key_0649 = { 55 26 [2] 71 28 [2] 5a 04 [2] 74 26 [2] 60 3d [2] 6f 27 [2] 71 3a [2] 73 3b [2] 68 3d [2] 74 3a [2] 68 15 }

  condition:
    any of them
}