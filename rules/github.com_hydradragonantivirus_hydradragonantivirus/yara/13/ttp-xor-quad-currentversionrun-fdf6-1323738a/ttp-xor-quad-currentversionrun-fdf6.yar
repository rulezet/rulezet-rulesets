rule TTP_XOR_QUAD_CurrentVersionRun_fdf6 {
  strings:
    $key_fdf6 = { ae 99 [2] 8a 97 [2] a1 bb [2] 8f 99 [2] 9b 82 [2] 94 98 [2] 8a 85 [2] 88 84 [2] 93 82 [2] 8f 85 [2] 93 aa }

  condition:
    any of them
}