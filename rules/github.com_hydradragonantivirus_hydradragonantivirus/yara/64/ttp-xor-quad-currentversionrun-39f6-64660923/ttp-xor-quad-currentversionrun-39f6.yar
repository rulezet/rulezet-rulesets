rule TTP_XOR_QUAD_CurrentVersionRun_39f6 {
  strings:
    $key_39f6 = { 6a 99 [2] 4e 97 [2] 65 bb [2] 4b 99 [2] 5f 82 [2] 50 98 [2] 4e 85 [2] 4c 84 [2] 57 82 [2] 4b 85 [2] 57 aa }

  condition:
    any of them
}