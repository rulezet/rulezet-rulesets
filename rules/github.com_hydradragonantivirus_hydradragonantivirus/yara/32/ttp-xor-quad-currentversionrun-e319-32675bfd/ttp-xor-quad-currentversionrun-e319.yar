rule TTP_XOR_QUAD_CurrentVersionRun_e319 {
  strings:
    $key_e319 = { b0 76 [2] 94 78 [2] bf 54 [2] 91 76 [2] 85 6d [2] 8a 77 [2] 94 6a [2] 96 6b [2] 8d 6d [2] 91 6a [2] 8d 45 }

  condition:
    any of them
}