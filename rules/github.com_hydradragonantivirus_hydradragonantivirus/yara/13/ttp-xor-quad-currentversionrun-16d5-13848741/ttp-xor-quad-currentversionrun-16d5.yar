rule TTP_XOR_QUAD_CurrentVersionRun_16d5 {
  strings:
    $key_16d5 = { 45 ba [2] 61 b4 [2] 4a 98 [2] 64 ba [2] 70 a1 [2] 7f bb [2] 61 a6 [2] 63 a7 [2] 78 a1 [2] 64 a6 [2] 78 89 }

  condition:
    any of them
}