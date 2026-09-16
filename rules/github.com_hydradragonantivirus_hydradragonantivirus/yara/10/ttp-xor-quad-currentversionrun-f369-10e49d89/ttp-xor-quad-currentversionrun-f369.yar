rule TTP_XOR_QUAD_CurrentVersionRun_f369 {
  strings:
    $key_f369 = { a0 06 [2] 84 08 [2] af 24 [2] 81 06 [2] 95 1d [2] 9a 07 [2] 84 1a [2] 86 1b [2] 9d 1d [2] 81 1a [2] 9d 35 }

  condition:
    any of them
}