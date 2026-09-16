rule TTP_XOR_QUAD_CurrentVersionRun_41f6 {
  strings:
    $key_41f6 = { 12 99 [2] 36 97 [2] 1d bb [2] 33 99 [2] 27 82 [2] 28 98 [2] 36 85 [2] 34 84 [2] 2f 82 [2] 33 85 [2] 2f aa }

  condition:
    any of them
}