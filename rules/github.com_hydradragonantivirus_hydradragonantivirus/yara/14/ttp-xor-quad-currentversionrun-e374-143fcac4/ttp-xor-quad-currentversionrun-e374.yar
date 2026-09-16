rule TTP_XOR_QUAD_CurrentVersionRun_e374 {
  strings:
    $key_e374 = { b0 1b [2] 94 15 [2] bf 39 [2] 91 1b [2] 85 00 [2] 8a 1a [2] 94 07 [2] 96 06 [2] 8d 00 [2] 91 07 [2] 8d 28 }

  condition:
    any of them
}