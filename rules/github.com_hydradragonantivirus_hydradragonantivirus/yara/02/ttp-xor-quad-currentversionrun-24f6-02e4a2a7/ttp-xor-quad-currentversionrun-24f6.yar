rule TTP_XOR_QUAD_CurrentVersionRun_24f6 {
  strings:
    $key_24f6 = { 77 99 [2] 53 97 [2] 78 bb [2] 56 99 [2] 42 82 [2] 4d 98 [2] 53 85 [2] 51 84 [2] 4a 82 [2] 56 85 [2] 4a aa }

  condition:
    any of them
}