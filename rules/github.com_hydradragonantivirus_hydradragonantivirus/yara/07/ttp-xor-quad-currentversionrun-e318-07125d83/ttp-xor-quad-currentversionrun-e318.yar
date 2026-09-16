rule TTP_XOR_QUAD_CurrentVersionRun_e318 {
  strings:
    $key_e318 = { b0 77 [2] 94 79 [2] bf 55 [2] 91 77 [2] 85 6c [2] 8a 76 [2] 94 6b [2] 96 6a [2] 8d 6c [2] 91 6b [2] 8d 44 }

  condition:
    any of them
}