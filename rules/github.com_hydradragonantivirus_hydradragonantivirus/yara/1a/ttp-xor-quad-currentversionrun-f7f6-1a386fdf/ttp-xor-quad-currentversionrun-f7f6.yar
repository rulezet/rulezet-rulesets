rule TTP_XOR_QUAD_CurrentVersionRun_f7f6 {
  strings:
    $key_f7f6 = { a4 99 [2] 80 97 [2] ab bb [2] 85 99 [2] 91 82 [2] 9e 98 [2] 80 85 [2] 82 84 [2] 99 82 [2] 85 85 [2] 99 aa }

  condition:
    any of them
}