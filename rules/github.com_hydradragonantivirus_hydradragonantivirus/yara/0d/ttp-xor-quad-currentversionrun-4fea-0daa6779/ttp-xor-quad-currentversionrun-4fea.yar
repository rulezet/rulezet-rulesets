rule TTP_XOR_QUAD_CurrentVersionRun_4fea {
  strings:
    $key_4fea = { 1c 85 [2] 38 8b [2] 13 a7 [2] 3d 85 [2] 29 9e [2] 26 84 [2] 38 99 [2] 3a 98 [2] 21 9e [2] 3d 99 [2] 21 b6 }

  condition:
    any of them
}