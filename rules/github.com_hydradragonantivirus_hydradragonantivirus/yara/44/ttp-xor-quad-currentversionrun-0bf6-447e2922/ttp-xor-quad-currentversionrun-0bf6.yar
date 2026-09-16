rule TTP_XOR_QUAD_CurrentVersionRun_0bf6 {
  strings:
    $key_0bf6 = { 58 99 [2] 7c 97 [2] 57 bb [2] 79 99 [2] 6d 82 [2] 62 98 [2] 7c 85 [2] 7e 84 [2] 65 82 [2] 79 85 [2] 65 aa }

  condition:
    any of them
}