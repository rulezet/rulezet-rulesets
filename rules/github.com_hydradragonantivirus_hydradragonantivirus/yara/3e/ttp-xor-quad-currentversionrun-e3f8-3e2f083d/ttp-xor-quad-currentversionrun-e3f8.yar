rule TTP_XOR_QUAD_CurrentVersionRun_e3f8 {
  strings:
    $key_e3f8 = { b0 97 [2] 94 99 [2] bf b5 [2] 91 97 [2] 85 8c [2] 8a 96 [2] 94 8b [2] 96 8a [2] 8d 8c [2] 91 8b [2] 8d a4 }

  condition:
    any of them
}