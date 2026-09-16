rule TTP_XOR_QUAD_CurrentVersionRun_6bf6 {
  strings:
    $key_6bf6 = { 38 99 [2] 1c 97 [2] 37 bb [2] 19 99 [2] 0d 82 [2] 02 98 [2] 1c 85 [2] 1e 84 [2] 05 82 [2] 19 85 [2] 05 aa }

  condition:
    any of them
}