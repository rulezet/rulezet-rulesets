rule TTP_XOR_QUAD_CurrentVersionRun_2249 {
  strings:
    $key_2249 = { 71 26 [2] 55 28 [2] 7e 04 [2] 50 26 [2] 44 3d [2] 4b 27 [2] 55 3a [2] 57 3b [2] 4c 3d [2] 50 3a [2] 4c 15 }

  condition:
    any of them
}