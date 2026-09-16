rule TTP_XOR_QUAD_CurrentVersionRun_38f6 {
  strings:
    $key_38f6 = { 6b 99 [2] 4f 97 [2] 64 bb [2] 4a 99 [2] 5e 82 [2] 51 98 [2] 4f 85 [2] 4d 84 [2] 56 82 [2] 4a 85 [2] 56 aa }

  condition:
    any of them
}