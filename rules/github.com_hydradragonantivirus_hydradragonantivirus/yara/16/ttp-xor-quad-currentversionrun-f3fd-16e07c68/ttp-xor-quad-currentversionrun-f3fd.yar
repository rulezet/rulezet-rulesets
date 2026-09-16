rule TTP_XOR_QUAD_CurrentVersionRun_f3fd {
  strings:
    $key_f3fd = { a0 92 [2] 84 9c [2] af b0 [2] 81 92 [2] 95 89 [2] 9a 93 [2] 84 8e [2] 86 8f [2] 9d 89 [2] 81 8e [2] 9d a1 }

  condition:
    any of them
}