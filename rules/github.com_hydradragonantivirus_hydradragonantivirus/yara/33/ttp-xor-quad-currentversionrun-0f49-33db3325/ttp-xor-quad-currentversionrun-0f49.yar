rule TTP_XOR_QUAD_CurrentVersionRun_0f49 {
  strings:
    $key_0f49 = { 5c 26 [2] 78 28 [2] 53 04 [2] 7d 26 [2] 69 3d [2] 66 27 [2] 78 3a [2] 7a 3b [2] 61 3d [2] 7d 3a [2] 61 15 }

  condition:
    any of them
}