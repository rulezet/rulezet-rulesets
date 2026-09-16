rule TTP_XOR_QUAD_CurrentVersionRun_ddd4 {
  strings:
    $key_ddd4 = { 8e bb [2] aa b5 [2] 81 99 [2] af bb [2] bb a0 [2] b4 ba [2] aa a7 [2] a8 a6 [2] b3 a0 [2] af a7 [2] b3 88 }

  condition:
    any of them
}