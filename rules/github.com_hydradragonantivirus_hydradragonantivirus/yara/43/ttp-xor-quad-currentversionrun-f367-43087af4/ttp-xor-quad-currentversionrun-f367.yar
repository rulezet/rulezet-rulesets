rule TTP_XOR_QUAD_CurrentVersionRun_f367 {
  strings:
    $key_f367 = { a0 08 [2] 84 06 [2] af 2a [2] 81 08 [2] 95 13 [2] 9a 09 [2] 84 14 [2] 86 15 [2] 9d 13 [2] 81 14 [2] 9d 3b }

  condition:
    any of them
}