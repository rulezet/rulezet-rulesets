rule TTP_XOR_QUAD_CurrentVersionRun_efc9 {
  strings:
    $key_efc9 = { bc a6 [2] 98 a8 [2] b3 84 [2] 9d a6 [2] 89 bd [2] 86 a7 [2] 98 ba [2] 9a bb [2] 81 bd [2] 9d ba [2] 81 95 }

  condition:
    any of them
}