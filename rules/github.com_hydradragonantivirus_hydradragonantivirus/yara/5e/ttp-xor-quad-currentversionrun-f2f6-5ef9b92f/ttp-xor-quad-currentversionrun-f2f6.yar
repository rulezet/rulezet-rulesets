rule TTP_XOR_QUAD_CurrentVersionRun_f2f6 {
  strings:
    $key_f2f6 = { a1 99 [2] 85 97 [2] ae bb [2] 80 99 [2] 94 82 [2] 9b 98 [2] 85 85 [2] 87 84 [2] 9c 82 [2] 80 85 [2] 9c aa }

  condition:
    any of them
}