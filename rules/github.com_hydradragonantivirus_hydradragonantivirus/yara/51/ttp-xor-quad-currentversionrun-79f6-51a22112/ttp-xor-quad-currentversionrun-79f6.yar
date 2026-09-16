rule TTP_XOR_QUAD_CurrentVersionRun_79f6 {
  strings:
    $key_79f6 = { 2a 99 [2] 0e 97 [2] 25 bb [2] 0b 99 [2] 1f 82 [2] 10 98 [2] 0e 85 [2] 0c 84 [2] 17 82 [2] 0b 85 [2] 17 aa }

  condition:
    any of them
}