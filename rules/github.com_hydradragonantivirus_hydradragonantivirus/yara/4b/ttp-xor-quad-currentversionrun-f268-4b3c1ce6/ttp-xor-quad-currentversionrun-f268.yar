rule TTP_XOR_QUAD_CurrentVersionRun_f268 {
  strings:
    $key_f268 = { a1 07 [2] 85 09 [2] ae 25 [2] 80 07 [2] 94 1c [2] 9b 06 [2] 85 1b [2] 87 1a [2] 9c 1c [2] 80 1b [2] 9c 34 }

  condition:
    any of them
}