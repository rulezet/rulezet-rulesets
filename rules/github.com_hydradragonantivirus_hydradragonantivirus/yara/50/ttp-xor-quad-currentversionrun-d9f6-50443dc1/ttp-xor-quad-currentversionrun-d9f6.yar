rule TTP_XOR_QUAD_CurrentVersionRun_d9f6 {
  strings:
    $key_d9f6 = { 8a 99 [2] ae 97 [2] 85 bb [2] ab 99 [2] bf 82 [2] b0 98 [2] ae 85 [2] ac 84 [2] b7 82 [2] ab 85 [2] b7 aa }

  condition:
    any of them
}