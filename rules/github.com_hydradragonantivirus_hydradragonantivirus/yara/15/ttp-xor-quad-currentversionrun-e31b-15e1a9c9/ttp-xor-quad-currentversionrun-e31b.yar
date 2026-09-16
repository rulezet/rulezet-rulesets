rule TTP_XOR_QUAD_CurrentVersionRun_e31b {
  strings:
    $key_e31b = { b0 74 [2] 94 7a [2] bf 56 [2] 91 74 [2] 85 6f [2] 8a 75 [2] 94 68 [2] 96 69 [2] 8d 6f [2] 91 68 [2] 8d 47 }

  condition:
    any of them
}