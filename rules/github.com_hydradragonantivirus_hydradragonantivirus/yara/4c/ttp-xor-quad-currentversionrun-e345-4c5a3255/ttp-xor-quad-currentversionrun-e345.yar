rule TTP_XOR_QUAD_CurrentVersionRun_e345 {
  strings:
    $key_e345 = { b0 2a [2] 94 24 [2] bf 08 [2] 91 2a [2] 85 31 [2] 8a 2b [2] 94 36 [2] 96 37 [2] 8d 31 [2] 91 36 [2] 8d 19 }

  condition:
    any of them
}