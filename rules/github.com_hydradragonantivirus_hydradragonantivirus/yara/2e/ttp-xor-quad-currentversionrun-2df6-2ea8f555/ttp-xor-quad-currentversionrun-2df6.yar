rule TTP_XOR_QUAD_CurrentVersionRun_2df6 {
  strings:
    $key_2df6 = { 7e 99 [2] 5a 97 [2] 71 bb [2] 5f 99 [2] 4b 82 [2] 44 98 [2] 5a 85 [2] 58 84 [2] 43 82 [2] 5f 85 [2] 43 aa }

  condition:
    any of them
}