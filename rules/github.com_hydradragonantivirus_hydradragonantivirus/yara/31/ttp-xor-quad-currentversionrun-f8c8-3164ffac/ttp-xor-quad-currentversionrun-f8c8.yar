rule TTP_XOR_QUAD_CurrentVersionRun_f8c8 {
  strings:
    $key_f8c8 = { ab a7 [2] 8f a9 [2] a4 85 [2] 8a a7 [2] 9e bc [2] 91 a6 [2] 8f bb [2] 8d ba [2] 96 bc [2] 8a bb [2] 96 94 }

  condition:
    any of them
}