rule TTP_XOR_QUAD_CurrentVersionRun_0ec9 {
  strings:
    $key_0ec9 = { 5d a6 [2] 79 a8 [2] 52 84 [2] 7c a6 [2] 68 bd [2] 67 a7 [2] 79 ba [2] 7b bb [2] 60 bd [2] 7c ba [2] 60 95 }

  condition:
    any of them
}