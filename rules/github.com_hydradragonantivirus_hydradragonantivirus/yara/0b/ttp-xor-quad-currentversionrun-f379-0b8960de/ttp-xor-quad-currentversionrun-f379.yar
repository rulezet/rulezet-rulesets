rule TTP_XOR_QUAD_CurrentVersionRun_f379 {
  strings:
    $key_f379 = { a0 16 [2] 84 18 [2] af 34 [2] 81 16 [2] 95 0d [2] 9a 17 [2] 84 0a [2] 86 0b [2] 9d 0d [2] 81 0a [2] 9d 25 }

  condition:
    any of them
}