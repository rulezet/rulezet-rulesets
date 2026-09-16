rule TTP_XOR_QUAD_CurrentVersionRun_7ff6 {
  strings:
    $key_7ff6 = { 2c 99 [2] 08 97 [2] 23 bb [2] 0d 99 [2] 19 82 [2] 16 98 [2] 08 85 [2] 0a 84 [2] 11 82 [2] 0d 85 [2] 11 aa }

  condition:
    any of them
}