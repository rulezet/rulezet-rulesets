rule TTP_XOR_QUAD_CurrentVersionRun_65f6 {
  strings:
    $key_65f6 = { 36 99 [2] 12 97 [2] 39 bb [2] 17 99 [2] 03 82 [2] 0c 98 [2] 12 85 [2] 10 84 [2] 0b 82 [2] 17 85 [2] 0b aa }

  condition:
    any of them
}