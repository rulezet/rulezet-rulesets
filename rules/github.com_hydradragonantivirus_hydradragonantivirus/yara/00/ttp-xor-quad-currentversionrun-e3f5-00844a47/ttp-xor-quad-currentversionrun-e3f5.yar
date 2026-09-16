rule TTP_XOR_QUAD_CurrentVersionRun_e3f5 {
  strings:
    $key_e3f5 = { b0 9a [2] 94 94 [2] bf b8 [2] 91 9a [2] 85 81 [2] 8a 9b [2] 94 86 [2] 96 87 [2] 8d 81 [2] 91 86 [2] 8d a9 }

  condition:
    any of them
}