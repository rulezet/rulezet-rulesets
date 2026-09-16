rule TTP_XOR_QUAD_CurrentVersionRun_f336 {
  strings:
    $key_f336 = { a0 59 [2] 84 57 [2] af 7b [2] 81 59 [2] 95 42 [2] 9a 58 [2] 84 45 [2] 86 44 [2] 9d 42 [2] 81 45 [2] 9d 6a }

  condition:
    any of them
}