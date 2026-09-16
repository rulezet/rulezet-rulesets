rule TTP_XOR_QUAD_CurrentVersionRun_f320 {
  strings:
    $key_f320 = { a0 4f [2] 84 41 [2] af 6d [2] 81 4f [2] 95 54 [2] 9a 4e [2] 84 53 [2] 86 52 [2] 9d 54 [2] 81 53 [2] 9d 7c }

  condition:
    any of them
}