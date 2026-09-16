rule TTP_XOR_QUAD_CurrentVersionRun_48ea {
  strings:
    $key_48ea = { 1b 85 [2] 3f 8b [2] 14 a7 [2] 3a 85 [2] 2e 9e [2] 21 84 [2] 3f 99 [2] 3d 98 [2] 26 9e [2] 3a 99 [2] 26 b6 }

  condition:
    any of them
}