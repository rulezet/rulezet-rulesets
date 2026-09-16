rule TTP_XOR_QUAD_CurrentVersionRun_e379 {
  strings:
    $key_e379 = { b0 16 [2] 94 18 [2] bf 34 [2] 91 16 [2] 85 0d [2] 8a 17 [2] 94 0a [2] 96 0b [2] 8d 0d [2] 91 0a [2] 8d 25 }

  condition:
    any of them
}