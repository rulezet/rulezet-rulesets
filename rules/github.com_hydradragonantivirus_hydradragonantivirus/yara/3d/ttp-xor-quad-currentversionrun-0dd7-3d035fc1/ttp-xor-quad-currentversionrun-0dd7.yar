rule TTP_XOR_QUAD_CurrentVersionRun_0dd7 {
  strings:
    $key_0dd7 = { 5e b8 [2] 7a b6 [2] 51 9a [2] 7f b8 [2] 6b a3 [2] 64 b9 [2] 7a a4 [2] 78 a5 [2] 63 a3 [2] 7f a4 [2] 63 8b }

  condition:
    any of them
}