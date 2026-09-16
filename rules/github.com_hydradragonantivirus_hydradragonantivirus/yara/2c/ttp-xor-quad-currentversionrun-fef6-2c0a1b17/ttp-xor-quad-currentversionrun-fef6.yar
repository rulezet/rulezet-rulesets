rule TTP_XOR_QUAD_CurrentVersionRun_fef6 {
  strings:
    $key_fef6 = { ad 99 [2] 89 97 [2] a2 bb [2] 8c 99 [2] 98 82 [2] 97 98 [2] 89 85 [2] 8b 84 [2] 90 82 [2] 8c 85 [2] 90 aa }

  condition:
    any of them
}