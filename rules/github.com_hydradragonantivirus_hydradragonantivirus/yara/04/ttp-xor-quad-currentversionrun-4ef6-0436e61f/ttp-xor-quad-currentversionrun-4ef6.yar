rule TTP_XOR_QUAD_CurrentVersionRun_4ef6 {
  strings:
    $key_4ef6 = { 1d 99 [2] 39 97 [2] 12 bb [2] 3c 99 [2] 28 82 [2] 27 98 [2] 39 85 [2] 3b 84 [2] 20 82 [2] 3c 85 [2] 20 aa }

  condition:
    any of them
}