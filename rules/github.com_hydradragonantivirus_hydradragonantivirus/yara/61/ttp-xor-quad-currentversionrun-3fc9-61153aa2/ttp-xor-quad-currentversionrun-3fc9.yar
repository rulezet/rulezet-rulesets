rule TTP_XOR_QUAD_CurrentVersionRun_3fc9 {
  strings:
    $key_3fc9 = { 6c a6 [2] 48 a8 [2] 63 84 [2] 4d a6 [2] 59 bd [2] 56 a7 [2] 48 ba [2] 4a bb [2] 51 bd [2] 4d ba [2] 51 95 }

  condition:
    any of them
}