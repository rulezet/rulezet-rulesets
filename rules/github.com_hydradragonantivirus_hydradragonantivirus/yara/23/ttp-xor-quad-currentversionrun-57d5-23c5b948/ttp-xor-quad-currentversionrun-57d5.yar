rule TTP_XOR_QUAD_CurrentVersionRun_57d5 {
  strings:
    $key_57d5 = { 04 ba [2] 20 b4 [2] 0b 98 [2] 25 ba [2] 31 a1 [2] 3e bb [2] 20 a6 [2] 22 a7 [2] 39 a1 [2] 25 a6 [2] 39 89 }

  condition:
    any of them
}