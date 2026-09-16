rule TTP_XOR_QUAD_CurrentVersionRun_1af6 {
  strings:
    $key_1af6 = { 49 99 [2] 6d 97 [2] 46 bb [2] 68 99 [2] 7c 82 [2] 73 98 [2] 6d 85 [2] 6f 84 [2] 74 82 [2] 68 85 [2] 74 aa }

  condition:
    any of them
}