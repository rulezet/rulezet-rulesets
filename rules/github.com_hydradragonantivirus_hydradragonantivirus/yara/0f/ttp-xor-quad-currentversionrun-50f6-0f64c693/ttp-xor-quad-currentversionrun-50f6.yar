rule TTP_XOR_QUAD_CurrentVersionRun_50f6 {
  strings:
    $key_50f6 = { 03 99 [2] 27 97 [2] 0c bb [2] 22 99 [2] 36 82 [2] 39 98 [2] 27 85 [2] 25 84 [2] 3e 82 [2] 22 85 [2] 3e aa }

  condition:
    any of them
}