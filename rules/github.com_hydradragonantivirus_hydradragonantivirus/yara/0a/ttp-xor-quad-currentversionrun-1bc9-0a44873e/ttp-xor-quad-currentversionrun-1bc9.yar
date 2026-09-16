rule TTP_XOR_QUAD_CurrentVersionRun_1bc9 {
  strings:
    $key_1bc9 = { 48 a6 [2] 6c a8 [2] 47 84 [2] 69 a6 [2] 7d bd [2] 72 a7 [2] 6c ba [2] 6e bb [2] 75 bd [2] 69 ba [2] 75 95 }

  condition:
    any of them
}