rule TTP_XOR_QUAD_CurrentVersionRun_78f6 {
  strings:
    $key_78f6 = { 2b 99 [2] 0f 97 [2] 24 bb [2] 0a 99 [2] 1e 82 [2] 11 98 [2] 0f 85 [2] 0d 84 [2] 16 82 [2] 0a 85 [2] 16 aa }

  condition:
    any of them
}