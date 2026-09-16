rule TTP_XOR_QUAD_CurrentVersionRun_35f6 {
  strings:
    $key_35f6 = { 66 99 [2] 42 97 [2] 69 bb [2] 47 99 [2] 53 82 [2] 5c 98 [2] 42 85 [2] 40 84 [2] 5b 82 [2] 47 85 [2] 5b aa }

  condition:
    any of them
}