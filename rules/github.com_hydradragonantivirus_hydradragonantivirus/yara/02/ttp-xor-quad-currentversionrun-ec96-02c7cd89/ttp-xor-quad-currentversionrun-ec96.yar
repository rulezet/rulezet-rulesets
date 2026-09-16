rule TTP_XOR_QUAD_CurrentVersionRun_ec96 {
  strings:
    $key_ec96 = { bf f9 [2] 9b f7 [2] b0 db [2] 9e f9 [2] 8a e2 [2] 85 f8 [2] 9b e5 [2] 99 e4 [2] 82 e2 [2] 9e e5 [2] 82 ca }

  condition:
    any of them
}