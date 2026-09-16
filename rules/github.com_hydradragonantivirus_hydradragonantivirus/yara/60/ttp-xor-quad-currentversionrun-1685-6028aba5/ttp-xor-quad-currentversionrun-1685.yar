rule TTP_XOR_QUAD_CurrentVersionRun_1685 {
  strings:
    $key_1685 = { 45 ea [2] 61 e4 [2] 4a c8 [2] 64 ea [2] 70 f1 [2] 7f eb [2] 61 f6 [2] 63 f7 [2] 78 f1 [2] 64 f6 [2] 78 d9 }

  condition:
    any of them
}