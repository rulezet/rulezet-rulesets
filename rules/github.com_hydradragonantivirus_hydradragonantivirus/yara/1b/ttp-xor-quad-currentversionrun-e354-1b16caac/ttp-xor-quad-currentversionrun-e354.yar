rule TTP_XOR_QUAD_CurrentVersionRun_e354 {
  strings:
    $key_e354 = { b0 3b [2] 94 35 [2] bf 19 [2] 91 3b [2] 85 20 [2] 8a 3a [2] 94 27 [2] 96 26 [2] 8d 20 [2] 91 27 [2] 8d 08 }

  condition:
    any of them
}