rule TTP_XOR_QUAD_CurrentVersionRun_1cf6 {
  strings:
    $key_1cf6 = { 4f 99 [2] 6b 97 [2] 40 bb [2] 6e 99 [2] 7a 82 [2] 75 98 [2] 6b 85 [2] 69 84 [2] 72 82 [2] 6e 85 [2] 72 aa }

  condition:
    any of them
}