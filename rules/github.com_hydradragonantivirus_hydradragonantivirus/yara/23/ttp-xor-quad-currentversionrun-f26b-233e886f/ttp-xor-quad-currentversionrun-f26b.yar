rule TTP_XOR_QUAD_CurrentVersionRun_f26b {
  strings:
    $key_f26b = { a1 04 [2] 85 0a [2] ae 26 [2] 80 04 [2] 94 1f [2] 9b 05 [2] 85 18 [2] 87 19 [2] 9c 1f [2] 80 18 [2] 9c 37 }

  condition:
    any of them
}