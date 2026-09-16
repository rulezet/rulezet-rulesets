rule TTP_XOR_QUAD_CurrentVersionRun_1df6 {
  strings:
    $key_1df6 = { 4e 99 [2] 6a 97 [2] 41 bb [2] 6f 99 [2] 7b 82 [2] 74 98 [2] 6a 85 [2] 68 84 [2] 73 82 [2] 6f 85 [2] 73 aa }

  condition:
    any of them
}