rule TTP_XOR_QUAD_CurrentVersionRun_37d5 {
  strings:
    $key_37d5 = { 64 ba [2] 40 b4 [2] 6b 98 [2] 45 ba [2] 51 a1 [2] 5e bb [2] 40 a6 [2] 42 a7 [2] 59 a1 [2] 45 a6 [2] 59 89 }

  condition:
    any of them
}