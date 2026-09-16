rule TTP_XOR_QUAD_CurrentVersionRun_f3fa {
  strings:
    $key_f3fa = { a0 95 [2] 84 9b [2] af b7 [2] 81 95 [2] 95 8e [2] 9a 94 [2] 84 89 [2] 86 88 [2] 9d 8e [2] 81 89 [2] 9d a6 }

  condition:
    any of them
}