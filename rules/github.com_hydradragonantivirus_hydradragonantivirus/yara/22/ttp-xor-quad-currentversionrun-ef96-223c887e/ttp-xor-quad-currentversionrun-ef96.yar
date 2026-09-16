rule TTP_XOR_QUAD_CurrentVersionRun_ef96 {
  strings:
    $key_ef96 = { bc f9 [2] 98 f7 [2] b3 db [2] 9d f9 [2] 89 e2 [2] 86 f8 [2] 98 e5 [2] 9a e4 [2] 81 e2 [2] 9d e5 [2] 81 ca }

  condition:
    any of them
}