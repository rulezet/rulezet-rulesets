rule TTP_XOR_QUAD_CurrentVersionRun_f269 {
  strings:
    $key_f269 = { a1 06 [2] 85 08 [2] ae 24 [2] 80 06 [2] 94 1d [2] 9b 07 [2] 85 1a [2] 87 1b [2] 9c 1d [2] 80 1a [2] 9c 35 }

  condition:
    any of them
}