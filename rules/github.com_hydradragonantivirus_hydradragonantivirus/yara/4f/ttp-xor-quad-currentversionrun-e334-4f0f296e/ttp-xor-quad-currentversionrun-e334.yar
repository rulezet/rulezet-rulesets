rule TTP_XOR_QUAD_CurrentVersionRun_e334 {
  strings:
    $key_e334 = { b0 5b [2] 94 55 [2] bf 79 [2] 91 5b [2] 85 40 [2] 8a 5a [2] 94 47 [2] 96 46 [2] 8d 40 [2] 91 47 [2] 8d 68 }

  condition:
    any of them
}