rule TTP_XOR_QUAD_CurrentVersionRun_f337 {
  strings:
    $key_f337 = { a0 58 [2] 84 56 [2] af 7a [2] 81 58 [2] 95 43 [2] 9a 59 [2] 84 44 [2] 86 45 [2] 9d 43 [2] 81 44 [2] 9d 6b }

  condition:
    any of them
}