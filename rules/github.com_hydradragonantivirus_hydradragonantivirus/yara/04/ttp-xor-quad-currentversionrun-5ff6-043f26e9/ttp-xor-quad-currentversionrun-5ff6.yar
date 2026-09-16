rule TTP_XOR_QUAD_CurrentVersionRun_5ff6 {
  strings:
    $key_5ff6 = { 0c 99 [2] 28 97 [2] 03 bb [2] 2d 99 [2] 39 82 [2] 36 98 [2] 28 85 [2] 2a 84 [2] 31 82 [2] 2d 85 [2] 31 aa }

  condition:
    any of them
}