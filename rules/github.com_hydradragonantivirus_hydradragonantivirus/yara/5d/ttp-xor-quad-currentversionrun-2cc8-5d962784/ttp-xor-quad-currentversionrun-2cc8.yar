rule TTP_XOR_QUAD_CurrentVersionRun_2cc8 {
  strings:
    $key_2cc8 = { 7f a7 [2] 5b a9 [2] 70 85 [2] 5e a7 [2] 4a bc [2] 45 a6 [2] 5b bb [2] 59 ba [2] 42 bc [2] 5e bb [2] 42 94 }

  condition:
    any of them
}