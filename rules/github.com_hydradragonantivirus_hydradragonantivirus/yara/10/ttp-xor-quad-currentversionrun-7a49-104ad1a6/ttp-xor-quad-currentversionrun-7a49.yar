rule TTP_XOR_QUAD_CurrentVersionRun_7a49 {
  strings:
    $key_7a49 = { 29 26 [2] 0d 28 [2] 26 04 [2] 08 26 [2] 1c 3d [2] 13 27 [2] 0d 3a [2] 0f 3b [2] 14 3d [2] 08 3a [2] 14 15 }

  condition:
    any of them
}