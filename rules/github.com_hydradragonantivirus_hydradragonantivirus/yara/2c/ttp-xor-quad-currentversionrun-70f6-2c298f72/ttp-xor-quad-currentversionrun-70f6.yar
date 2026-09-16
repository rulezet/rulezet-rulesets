rule TTP_XOR_QUAD_CurrentVersionRun_70f6 {
  strings:
    $key_70f6 = { 23 99 [2] 07 97 [2] 2c bb [2] 02 99 [2] 16 82 [2] 19 98 [2] 07 85 [2] 05 84 [2] 1e 82 [2] 02 85 [2] 1e aa }

  condition:
    any of them
}