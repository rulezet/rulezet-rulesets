rule TTP_XOR_QUAD_CurrentVersionRun_3b49 {
  strings:
    $key_3b49 = { 68 26 [2] 4c 28 [2] 67 04 [2] 49 26 [2] 5d 3d [2] 52 27 [2] 4c 3a [2] 4e 3b [2] 55 3d [2] 49 3a [2] 55 15 }

  condition:
    any of them
}