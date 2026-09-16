rule TTP_XOR_QUAD_CurrentVersionRun_e338 {
  strings:
    $key_e338 = { b0 57 [2] 94 59 [2] bf 75 [2] 91 57 [2] 85 4c [2] 8a 56 [2] 94 4b [2] 96 4a [2] 8d 4c [2] 91 4b [2] 8d 64 }

  condition:
    any of them
}