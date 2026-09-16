rule TTP_XOR_QUAD_CurrentVersionRun_e356 {
  strings:
    $key_e356 = { b0 39 [2] 94 37 [2] bf 1b [2] 91 39 [2] 85 22 [2] 8a 38 [2] 94 25 [2] 96 24 [2] 8d 22 [2] 91 25 [2] 8d 0a }

  condition:
    any of them
}