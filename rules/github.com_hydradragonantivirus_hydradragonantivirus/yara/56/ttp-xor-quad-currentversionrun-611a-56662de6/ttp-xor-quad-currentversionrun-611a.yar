rule TTP_XOR_QUAD_CurrentVersionRun_611a {
  strings:
    $key_611a = { 32 75 [2] 16 7b [2] 3d 57 [2] 13 75 [2] 07 6e [2] 08 74 [2] 16 69 [2] 14 68 [2] 0f 6e [2] 13 69 [2] 0f 46 }

  condition:
    any of them
}