rule TTP_XOR_QUAD_CurrentVersionRun_eef6 {
  strings:
    $key_eef6 = { bd 99 [2] 99 97 [2] b2 bb [2] 9c 99 [2] 88 82 [2] 87 98 [2] 99 85 [2] 9b 84 [2] 80 82 [2] 9c 85 [2] 80 aa }

  condition:
    any of them
}