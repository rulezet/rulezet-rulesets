rule TTP_XOR_QUAD_CurrentVersionRun_f256 {
  strings:
    $key_f256 = { a1 39 [2] 85 37 [2] ae 1b [2] 80 39 [2] 94 22 [2] 9b 38 [2] 85 25 [2] 87 24 [2] 9c 22 [2] 80 25 [2] 9c 0a }

  condition:
    any of them
}