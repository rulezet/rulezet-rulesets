rule TTP_XOR_QUAD_CurrentVersionRun_1180 {
  strings:
    $key_1180 = { 42 ef [2] 66 e1 [2] 4d cd [2] 63 ef [2] 77 f4 [2] 78 ee [2] 66 f3 [2] 64 f2 [2] 7f f4 [2] 63 f3 [2] 7f dc }

  condition:
    any of them
}