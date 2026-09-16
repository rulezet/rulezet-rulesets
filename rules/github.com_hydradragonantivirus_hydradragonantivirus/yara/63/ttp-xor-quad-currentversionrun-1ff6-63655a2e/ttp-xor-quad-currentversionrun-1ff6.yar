rule TTP_XOR_QUAD_CurrentVersionRun_1ff6 {
  strings:
    $key_1ff6 = { 4c 99 [2] 68 97 [2] 43 bb [2] 6d 99 [2] 79 82 [2] 76 98 [2] 68 85 [2] 6a 84 [2] 71 82 [2] 6d 85 [2] 71 aa }

  condition:
    any of them
}