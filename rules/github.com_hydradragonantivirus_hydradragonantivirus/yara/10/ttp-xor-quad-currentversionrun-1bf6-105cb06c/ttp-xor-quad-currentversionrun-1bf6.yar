rule TTP_XOR_QUAD_CurrentVersionRun_1bf6 {
  strings:
    $key_1bf6 = { 48 99 [2] 6c 97 [2] 47 bb [2] 69 99 [2] 7d 82 [2] 72 98 [2] 6c 85 [2] 6e 84 [2] 75 82 [2] 69 85 [2] 75 aa }

  condition:
    any of them
}