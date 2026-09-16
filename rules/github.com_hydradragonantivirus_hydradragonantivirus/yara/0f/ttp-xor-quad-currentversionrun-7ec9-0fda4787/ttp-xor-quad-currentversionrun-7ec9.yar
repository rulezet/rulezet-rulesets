rule TTP_XOR_QUAD_CurrentVersionRun_7ec9 {
  strings:
    $key_7ec9 = { 2d a6 [2] 09 a8 [2] 22 84 [2] 0c a6 [2] 18 bd [2] 17 a7 [2] 09 ba [2] 0b bb [2] 10 bd [2] 0c ba [2] 10 95 }

  condition:
    any of them
}