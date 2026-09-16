rule TTP_XOR_QUAD_CurrentVersionRun_e3fa {
  strings:
    $key_e3fa = { b0 95 [2] 94 9b [2] bf b7 [2] 91 95 [2] 85 8e [2] 8a 94 [2] 94 89 [2] 96 88 [2] 8d 8e [2] 91 89 [2] 8d a6 }

  condition:
    any of them
}