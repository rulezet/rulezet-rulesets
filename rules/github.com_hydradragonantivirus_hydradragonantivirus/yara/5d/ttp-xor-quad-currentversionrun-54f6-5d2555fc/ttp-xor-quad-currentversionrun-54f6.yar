rule TTP_XOR_QUAD_CurrentVersionRun_54f6 {
  strings:
    $key_54f6 = { 07 99 [2] 23 97 [2] 08 bb [2] 26 99 [2] 32 82 [2] 3d 98 [2] 23 85 [2] 21 84 [2] 3a 82 [2] 26 85 [2] 3a aa }

  condition:
    any of them
}