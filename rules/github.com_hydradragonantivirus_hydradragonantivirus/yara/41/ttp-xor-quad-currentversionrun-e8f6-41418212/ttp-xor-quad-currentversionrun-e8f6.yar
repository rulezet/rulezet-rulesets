rule TTP_XOR_QUAD_CurrentVersionRun_e8f6 {
  strings:
    $key_e8f6 = { bb 99 [2] 9f 97 [2] b4 bb [2] 9a 99 [2] 8e 82 [2] 81 98 [2] 9f 85 [2] 9d 84 [2] 86 82 [2] 9a 85 [2] 86 aa }

  condition:
    any of them
}