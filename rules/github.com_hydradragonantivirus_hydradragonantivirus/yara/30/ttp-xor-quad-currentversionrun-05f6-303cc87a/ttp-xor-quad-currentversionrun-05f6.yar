rule TTP_XOR_QUAD_CurrentVersionRun_05f6 {
  strings:
    $key_05f6 = { 56 99 [2] 72 97 [2] 59 bb [2] 77 99 [2] 63 82 [2] 6c 98 [2] 72 85 [2] 70 84 [2] 6b 82 [2] 77 85 [2] 6b aa }

  condition:
    any of them
}