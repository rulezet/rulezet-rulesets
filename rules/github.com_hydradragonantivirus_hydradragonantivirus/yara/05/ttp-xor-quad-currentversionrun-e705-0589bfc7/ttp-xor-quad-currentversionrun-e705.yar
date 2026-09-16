rule TTP_XOR_QUAD_CurrentVersionRun_e705 {
  strings:
    $key_e705 = { b4 6a [2] 90 64 [2] bb 48 [2] 95 6a [2] 81 71 [2] 8e 6b [2] 90 76 [2] 92 77 [2] 89 71 [2] 95 76 [2] 89 59 }

  condition:
    any of them
}