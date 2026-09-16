rule TTP_XOR_QUAD_CurrentVersionRun_f21b {
  strings:
    $key_f21b = { a1 74 [2] 85 7a [2] ae 56 [2] 80 74 [2] 94 6f [2] 9b 75 [2] 85 68 [2] 87 69 [2] 9c 6f [2] 80 68 [2] 9c 47 }

  condition:
    any of them
}