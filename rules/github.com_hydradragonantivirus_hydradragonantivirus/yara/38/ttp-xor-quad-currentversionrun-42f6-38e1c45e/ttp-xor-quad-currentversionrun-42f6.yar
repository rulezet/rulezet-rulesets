rule TTP_XOR_QUAD_CurrentVersionRun_42f6 {
  strings:
    $key_42f6 = { 11 99 [2] 35 97 [2] 1e bb [2] 30 99 [2] 24 82 [2] 2b 98 [2] 35 85 [2] 37 84 [2] 2c 82 [2] 30 85 [2] 2c aa }

  condition:
    any of them
}