rule TTP_XOR_QUAD_CurrentVersionRun_dff6 {
  strings:
    $key_dff6 = { 8c 99 [2] a8 97 [2] 83 bb [2] ad 99 [2] b9 82 [2] b6 98 [2] a8 85 [2] aa 84 [2] b1 82 [2] ad 85 [2] b1 aa }

  condition:
    any of them
}