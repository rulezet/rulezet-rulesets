rule TTP_XOR_QUAD_CurrentVersionRun_1ef6 {
  strings:
    $key_1ef6 = { 4d 99 [2] 69 97 [2] 42 bb [2] 6c 99 [2] 78 82 [2] 77 98 [2] 69 85 [2] 6b 84 [2] 70 82 [2] 6c 85 [2] 70 aa }

  condition:
    any of them
}