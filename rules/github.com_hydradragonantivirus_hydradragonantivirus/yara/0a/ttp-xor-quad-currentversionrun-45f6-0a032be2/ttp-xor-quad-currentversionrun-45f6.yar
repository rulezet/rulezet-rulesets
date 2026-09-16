rule TTP_XOR_QUAD_CurrentVersionRun_45f6 {
  strings:
    $key_45f6 = { 16 99 [2] 32 97 [2] 19 bb [2] 37 99 [2] 23 82 [2] 2c 98 [2] 32 85 [2] 30 84 [2] 2b 82 [2] 37 85 [2] 2b aa }

  condition:
    any of them
}