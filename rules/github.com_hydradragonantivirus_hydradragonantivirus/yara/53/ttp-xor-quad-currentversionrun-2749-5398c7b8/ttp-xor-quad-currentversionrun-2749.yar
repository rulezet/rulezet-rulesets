rule TTP_XOR_QUAD_CurrentVersionRun_2749 {
  strings:
    $key_2749 = { 74 26 [2] 50 28 [2] 7b 04 [2] 55 26 [2] 41 3d [2] 4e 27 [2] 50 3a [2] 52 3b [2] 49 3d [2] 55 3a [2] 49 15 }

  condition:
    any of them
}