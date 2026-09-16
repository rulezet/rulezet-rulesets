rule TTP_XOR_QUAD_CurrentVersionRun_7bf6 {
  strings:
    $key_7bf6 = { 28 99 [2] 0c 97 [2] 27 bb [2] 09 99 [2] 1d 82 [2] 12 98 [2] 0c 85 [2] 0e 84 [2] 15 82 [2] 09 85 [2] 15 aa }

  condition:
    any of them
}