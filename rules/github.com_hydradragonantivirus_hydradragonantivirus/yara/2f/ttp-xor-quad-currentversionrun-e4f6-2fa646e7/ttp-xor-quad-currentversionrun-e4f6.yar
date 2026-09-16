rule TTP_XOR_QUAD_CurrentVersionRun_e4f6 {
  strings:
    $key_e4f6 = { b7 99 [2] 93 97 [2] b8 bb [2] 96 99 [2] 82 82 [2] 8d 98 [2] 93 85 [2] 91 84 [2] 8a 82 [2] 96 85 [2] 8a aa }

  condition:
    any of them
}