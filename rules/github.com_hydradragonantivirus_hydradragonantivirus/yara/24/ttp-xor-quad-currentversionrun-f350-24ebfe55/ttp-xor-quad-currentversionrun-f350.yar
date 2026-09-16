rule TTP_XOR_QUAD_CurrentVersionRun_f350 {
  strings:
    $key_f350 = { a0 3f [2] 84 31 [2] af 1d [2] 81 3f [2] 95 24 [2] 9a 3e [2] 84 23 [2] 86 22 [2] 9d 24 [2] 81 23 [2] 9d 0c }

  condition:
    any of them
}