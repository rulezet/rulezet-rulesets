rule TTP_XOR_QUAD_CurrentVersionRun_e359 {
  strings:
    $key_e359 = { b0 36 [2] 94 38 [2] bf 14 [2] 91 36 [2] 85 2d [2] 8a 37 [2] 94 2a [2] 96 2b [2] 8d 2d [2] 91 2a [2] 8d 05 }

  condition:
    any of them
}