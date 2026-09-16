rule TTP_XOR_QUAD_CurrentVersionRun_f3f9 {
  strings:
    $key_f3f9 = { a0 96 [2] 84 98 [2] af b4 [2] 81 96 [2] 95 8d [2] 9a 97 [2] 84 8a [2] 86 8b [2] 9d 8d [2] 81 8a [2] 9d a5 }

  condition:
    any of them
}