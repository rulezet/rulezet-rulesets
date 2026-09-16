rule TTP_XOR_QUAD_CurrentVersionRun_bef6 {
  strings:
    $key_bef6 = { ed 99 [2] c9 97 [2] e2 bb [2] cc 99 [2] d8 82 [2] d7 98 [2] c9 85 [2] cb 84 [2] d0 82 [2] cc 85 [2] d0 aa }

  condition:
    any of them
}