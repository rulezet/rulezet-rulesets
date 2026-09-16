rule TTP_XOR_QUAD_CurrentVersionRun_f456 {
  strings:
    $key_f456 = { a7 39 [2] 83 37 [2] a8 1b [2] 86 39 [2] 92 22 [2] 9d 38 [2] 83 25 [2] 81 24 [2] 9a 22 [2] 86 25 [2] 9a 0a }

  condition:
    any of them
}