rule TTP_XOR_QUAD_CurrentVersionRun_48c8 {
  strings:
    $key_48c8 = { 1b a7 [2] 3f a9 [2] 14 85 [2] 3a a7 [2] 2e bc [2] 21 a6 [2] 3f bb [2] 3d ba [2] 26 bc [2] 3a bb [2] 26 94 }

  condition:
    any of them
}