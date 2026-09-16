rule TTP_XOR_QUAD_CurrentVersionRun_e3e8 {
  strings:
    $key_e3e8 = { b0 87 [2] 94 89 [2] bf a5 [2] 91 87 [2] 85 9c [2] 8a 86 [2] 94 9b [2] 96 9a [2] 8d 9c [2] 91 9b [2] 8d b4 }

  condition:
    any of them
}