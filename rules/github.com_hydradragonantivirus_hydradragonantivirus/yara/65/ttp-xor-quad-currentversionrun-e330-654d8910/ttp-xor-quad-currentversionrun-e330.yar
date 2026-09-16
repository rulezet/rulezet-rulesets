rule TTP_XOR_QUAD_CurrentVersionRun_e330 {
  strings:
    $key_e330 = { b0 5f [2] 94 51 [2] bf 7d [2] 91 5f [2] 85 44 [2] 8a 5e [2] 94 43 [2] 96 42 [2] 8d 44 [2] 91 43 [2] 8d 6c }

  condition:
    any of them
}