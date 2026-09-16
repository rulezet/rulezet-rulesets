rule TTP_XOR_QUAD_CurrentVersionRun_e307 {
  strings:
    $key_e307 = { b0 68 [2] 94 66 [2] bf 4a [2] 91 68 [2] 85 73 [2] 8a 69 [2] 94 74 [2] 96 75 [2] 8d 73 [2] 91 74 [2] 8d 5b }

  condition:
    any of them
}