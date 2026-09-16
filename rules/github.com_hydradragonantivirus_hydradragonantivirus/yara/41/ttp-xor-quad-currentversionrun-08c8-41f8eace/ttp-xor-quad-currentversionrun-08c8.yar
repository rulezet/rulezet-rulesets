rule TTP_XOR_QUAD_CurrentVersionRun_08c8 {
  strings:
    $key_08c8 = { 5b a7 [2] 7f a9 [2] 54 85 [2] 7a a7 [2] 6e bc [2] 61 a6 [2] 7f bb [2] 7d ba [2] 66 bc [2] 7a bb [2] 66 94 }

  condition:
    any of them
}