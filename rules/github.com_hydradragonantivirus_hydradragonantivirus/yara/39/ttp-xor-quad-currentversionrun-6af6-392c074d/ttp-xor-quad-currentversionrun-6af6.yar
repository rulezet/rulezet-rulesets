rule TTP_XOR_QUAD_CurrentVersionRun_6af6 {
  strings:
    $key_6af6 = { 39 99 [2] 1d 97 [2] 36 bb [2] 18 99 [2] 0c 82 [2] 03 98 [2] 1d 85 [2] 1f 84 [2] 04 82 [2] 18 85 [2] 04 aa }

  condition:
    any of them
}