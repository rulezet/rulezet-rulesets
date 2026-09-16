rule TTP_XOR_QUAD_CurrentVersionRun_579d {
  strings:
    $key_579d = { 04 f2 [2] 20 fc [2] 0b d0 [2] 25 f2 [2] 31 e9 [2] 3e f3 [2] 20 ee [2] 22 ef [2] 39 e9 [2] 25 ee [2] 39 c1 }

  condition:
    any of them
}