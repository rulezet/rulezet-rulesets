rule TTP_XOR_QUAD_CurrentVersionRun_309c {
  strings:
    $key_309c = { 63 f3 [2] 47 fd [2] 6c d1 [2] 42 f3 [2] 56 e8 [2] 59 f2 [2] 47 ef [2] 45 ee [2] 5e e8 [2] 42 ef [2] 5e c0 }

  condition:
    any of them
}