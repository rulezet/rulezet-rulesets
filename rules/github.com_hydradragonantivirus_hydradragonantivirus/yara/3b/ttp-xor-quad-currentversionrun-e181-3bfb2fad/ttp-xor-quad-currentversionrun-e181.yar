rule TTP_XOR_QUAD_CurrentVersionRun_e181 {
  strings:
    $key_e181 = { b2 ee [2] 96 e0 [2] bd cc [2] 93 ee [2] 87 f5 [2] 88 ef [2] 96 f2 [2] 94 f3 [2] 8f f5 [2] 93 f2 [2] 8f dd }

  condition:
    any of them
}