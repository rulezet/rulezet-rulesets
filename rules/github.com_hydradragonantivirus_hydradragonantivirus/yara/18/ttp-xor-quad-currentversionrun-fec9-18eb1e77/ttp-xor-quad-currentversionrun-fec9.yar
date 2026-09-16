rule TTP_XOR_QUAD_CurrentVersionRun_fec9 {
  strings:
    $key_fec9 = { ad a6 [2] 89 a8 [2] a2 84 [2] 8c a6 [2] 98 bd [2] 97 a7 [2] 89 ba [2] 8b bb [2] 90 bd [2] 8c ba [2] 90 95 }

  condition:
    any of them
}