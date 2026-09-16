rule TTP_XOR_QUAD_CurrentVersionRun_4df6 {
  strings:
    $key_4df6 = { 1e 99 [2] 3a 97 [2] 11 bb [2] 3f 99 [2] 2b 82 [2] 24 98 [2] 3a 85 [2] 38 84 [2] 23 82 [2] 3f 85 [2] 23 aa }

  condition:
    any of them
}