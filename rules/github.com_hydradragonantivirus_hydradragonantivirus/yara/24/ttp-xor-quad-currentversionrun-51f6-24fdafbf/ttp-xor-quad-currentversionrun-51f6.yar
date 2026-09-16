rule TTP_XOR_QUAD_CurrentVersionRun_51f6 {
  strings:
    $key_51f6 = { 02 99 [2] 26 97 [2] 0d bb [2] 23 99 [2] 37 82 [2] 38 98 [2] 26 85 [2] 24 84 [2] 3f 82 [2] 23 85 [2] 3f aa }

  condition:
    any of them
}