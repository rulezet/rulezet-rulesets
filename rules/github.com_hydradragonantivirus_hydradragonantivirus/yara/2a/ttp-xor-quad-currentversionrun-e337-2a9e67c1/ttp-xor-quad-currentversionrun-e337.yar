rule TTP_XOR_QUAD_CurrentVersionRun_e337 {
  strings:
    $key_e337 = { b0 58 [2] 94 56 [2] bf 7a [2] 91 58 [2] 85 43 [2] 8a 59 [2] 94 44 [2] 96 45 [2] 8d 43 [2] 91 44 [2] 8d 6b }

  condition:
    any of them
}