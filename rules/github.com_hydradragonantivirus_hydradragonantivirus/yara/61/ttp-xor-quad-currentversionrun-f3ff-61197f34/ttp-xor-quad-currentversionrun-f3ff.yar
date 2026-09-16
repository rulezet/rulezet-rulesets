rule TTP_XOR_QUAD_CurrentVersionRun_f3ff {
  strings:
    $key_f3ff = { a0 90 [2] 84 9e [2] af b2 [2] 81 90 [2] 95 8b [2] 9a 91 [2] 84 8c [2] 86 8d [2] 9d 8b [2] 81 8c [2] 9d a3 }

  condition:
    any of them
}