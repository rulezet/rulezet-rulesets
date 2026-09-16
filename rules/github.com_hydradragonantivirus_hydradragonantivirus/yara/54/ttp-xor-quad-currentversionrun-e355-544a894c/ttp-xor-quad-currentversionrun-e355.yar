rule TTP_XOR_QUAD_CurrentVersionRun_e355 {
  strings:
    $key_e355 = { b0 3a [2] 94 34 [2] bf 18 [2] 91 3a [2] 85 21 [2] 8a 3b [2] 94 26 [2] 96 27 [2] 8d 21 [2] 91 26 [2] 8d 09 }

  condition:
    any of them
}