rule TTP_XOR_QUAD_CurrentVersionRun_4ff6 {
  strings:
    $key_4ff6 = { 1c 99 [2] 38 97 [2] 13 bb [2] 3d 99 [2] 29 82 [2] 26 98 [2] 38 85 [2] 3a 84 [2] 21 82 [2] 3d 85 [2] 21 aa }

  condition:
    any of them
}