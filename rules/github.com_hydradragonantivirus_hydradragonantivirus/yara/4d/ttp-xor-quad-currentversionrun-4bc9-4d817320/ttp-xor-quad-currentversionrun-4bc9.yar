rule TTP_XOR_QUAD_CurrentVersionRun_4bc9 {
  strings:
    $key_4bc9 = { 18 a6 [2] 3c a8 [2] 17 84 [2] 39 a6 [2] 2d bd [2] 22 a7 [2] 3c ba [2] 3e bb [2] 25 bd [2] 39 ba [2] 25 95 }

  condition:
    any of them
}