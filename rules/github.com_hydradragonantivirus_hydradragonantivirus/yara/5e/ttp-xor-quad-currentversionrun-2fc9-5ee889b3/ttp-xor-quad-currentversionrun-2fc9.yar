rule TTP_XOR_QUAD_CurrentVersionRun_2fc9 {
  strings:
    $key_2fc9 = { 7c a6 [2] 58 a8 [2] 73 84 [2] 5d a6 [2] 49 bd [2] 46 a7 [2] 58 ba [2] 5a bb [2] 41 bd [2] 5d ba [2] 41 95 }

  condition:
    any of them
}