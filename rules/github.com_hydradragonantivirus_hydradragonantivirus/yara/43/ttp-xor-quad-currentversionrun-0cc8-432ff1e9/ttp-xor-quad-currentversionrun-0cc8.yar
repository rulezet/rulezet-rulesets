rule TTP_XOR_QUAD_CurrentVersionRun_0cc8 {
  strings:
    $key_0cc8 = { 5f a7 [2] 7b a9 [2] 50 85 [2] 7e a7 [2] 6a bc [2] 65 a6 [2] 7b bb [2] 79 ba [2] 62 bc [2] 7e bb [2] 62 94 }

  condition:
    any of them
}