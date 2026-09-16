rule TTP_XOR_QUAD_CurrentVersionRun_4af6 {
  strings:
    $key_4af6 = { 19 99 [2] 3d 97 [2] 16 bb [2] 38 99 [2] 2c 82 [2] 23 98 [2] 3d 85 [2] 3f 84 [2] 24 82 [2] 38 85 [2] 24 aa }

  condition:
    any of them
}