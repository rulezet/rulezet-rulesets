rule TTP_XOR_QUAD_CurrentVersionRun_b5f6 {
  strings:
    $key_b5f6 = { e6 99 [2] c2 97 [2] e9 bb [2] c7 99 [2] d3 82 [2] dc 98 [2] c2 85 [2] c0 84 [2] db 82 [2] c7 85 [2] db aa }

  condition:
    any of them
}