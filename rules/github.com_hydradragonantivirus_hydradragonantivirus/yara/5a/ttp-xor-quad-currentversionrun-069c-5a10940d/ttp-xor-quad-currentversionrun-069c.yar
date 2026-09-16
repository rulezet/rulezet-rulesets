rule TTP_XOR_QUAD_CurrentVersionRun_069c {
  strings:
    $key_069c = { 55 f3 [2] 71 fd [2] 5a d1 [2] 74 f3 [2] 60 e8 [2] 6f f2 [2] 71 ef [2] 73 ee [2] 68 e8 [2] 74 ef [2] 68 c0 }

  condition:
    any of them
}