rule TTP_XOR_QUAD_CurrentVersionRun_44f6 {
  strings:
    $key_44f6 = { 17 99 [2] 33 97 [2] 18 bb [2] 36 99 [2] 22 82 [2] 2d 98 [2] 33 85 [2] 31 84 [2] 2a 82 [2] 36 85 [2] 2a aa }

  condition:
    any of them
}