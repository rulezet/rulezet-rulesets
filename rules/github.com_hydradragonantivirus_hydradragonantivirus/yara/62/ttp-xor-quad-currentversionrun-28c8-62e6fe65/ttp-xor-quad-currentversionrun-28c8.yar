rule TTP_XOR_QUAD_CurrentVersionRun_28c8 {
  strings:
    $key_28c8 = { 7b a7 [2] 5f a9 [2] 74 85 [2] 5a a7 [2] 4e bc [2] 41 a6 [2] 5f bb [2] 5d ba [2] 46 bc [2] 5a bb [2] 46 94 }

  condition:
    any of them
}