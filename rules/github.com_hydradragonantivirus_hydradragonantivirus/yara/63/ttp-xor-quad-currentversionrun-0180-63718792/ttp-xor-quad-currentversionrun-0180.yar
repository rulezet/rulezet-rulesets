rule TTP_XOR_QUAD_CurrentVersionRun_0180 {
  strings:
    $key_0180 = { 52 ef [2] 76 e1 [2] 5d cd [2] 73 ef [2] 67 f4 [2] 68 ee [2] 76 f3 [2] 74 f2 [2] 6f f4 [2] 73 f3 [2] 6f dc }

  condition:
    any of them
}