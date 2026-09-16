rule TTP_XOR_QUAD_CurrentVersionRun_4437 {
  strings:
    $key_4437 = { 17 58 [2] 33 56 [2] 18 7a [2] 36 58 [2] 22 43 [2] 2d 59 [2] 33 44 [2] 31 45 [2] 2a 43 [2] 36 44 [2] 2a 6b }

  condition:
    any of them
}