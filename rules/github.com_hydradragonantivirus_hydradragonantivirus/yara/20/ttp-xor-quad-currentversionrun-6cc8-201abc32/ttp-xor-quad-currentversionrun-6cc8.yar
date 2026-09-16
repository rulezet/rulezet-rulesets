rule TTP_XOR_QUAD_CurrentVersionRun_6cc8 {
  strings:
    $key_6cc8 = { 3f a7 [2] 1b a9 [2] 30 85 [2] 1e a7 [2] 0a bc [2] 05 a6 [2] 1b bb [2] 19 ba [2] 02 bc [2] 1e bb [2] 02 94 }

  condition:
    any of them
}