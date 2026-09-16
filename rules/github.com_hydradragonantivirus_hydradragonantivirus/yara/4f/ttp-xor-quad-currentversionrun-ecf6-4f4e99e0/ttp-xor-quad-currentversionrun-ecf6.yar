rule TTP_XOR_QUAD_CurrentVersionRun_ecf6 {
  strings:
    $key_ecf6 = { bf 99 [2] 9b 97 [2] b0 bb [2] 9e 99 [2] 8a 82 [2] 85 98 [2] 9b 85 [2] 99 84 [2] 82 82 [2] 9e 85 [2] 82 aa }

  condition:
    any of them
}