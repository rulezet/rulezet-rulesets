rule TTP_XOR_QUAD_CurrentVersionRun_08f6 {
  strings:
    $key_08f6 = { 5b 99 [2] 7f 97 [2] 54 bb [2] 7a 99 [2] 6e 82 [2] 61 98 [2] 7f 85 [2] 7d 84 [2] 66 82 [2] 7a 85 [2] 66 aa }

  condition:
    any of them
}