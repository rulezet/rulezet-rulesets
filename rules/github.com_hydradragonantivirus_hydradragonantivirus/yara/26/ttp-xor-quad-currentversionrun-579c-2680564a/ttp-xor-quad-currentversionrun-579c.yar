rule TTP_XOR_QUAD_CurrentVersionRun_579c {
  strings:
    $key_579c = { 04 f3 [2] 20 fd [2] 0b d1 [2] 25 f3 [2] 31 e8 [2] 3e f2 [2] 20 ef [2] 22 ee [2] 39 e8 [2] 25 ef [2] 39 c0 }

  condition:
    any of them
}