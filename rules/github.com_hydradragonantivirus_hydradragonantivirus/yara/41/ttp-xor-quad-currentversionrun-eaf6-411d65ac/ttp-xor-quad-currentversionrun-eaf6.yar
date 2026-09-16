rule TTP_XOR_QUAD_CurrentVersionRun_eaf6 {
  strings:
    $key_eaf6 = { b9 99 [2] 9d 97 [2] b6 bb [2] 98 99 [2] 8c 82 [2] 83 98 [2] 9d 85 [2] 9f 84 [2] 84 82 [2] 98 85 [2] 84 aa }

  condition:
    any of them
}