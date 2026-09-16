rule TTP_XOR_QUAD_CurrentVersionRun_6dd7 {
  strings:
    $key_6dd7 = { 3e b8 [2] 1a b6 [2] 31 9a [2] 1f b8 [2] 0b a3 [2] 04 b9 [2] 1a a4 [2] 18 a5 [2] 03 a3 [2] 1f a4 [2] 03 8b }

  condition:
    any of them
}