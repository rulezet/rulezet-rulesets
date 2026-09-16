rule TTP_XOR_QUAD_CurrentVersionRun_309d {
  strings:
    $key_309d = { 63 f2 [2] 47 fc [2] 6c d0 [2] 42 f2 [2] 56 e9 [2] 59 f3 [2] 47 ee [2] 45 ef [2] 5e e9 [2] 42 ee [2] 5e c1 }

  condition:
    any of them
}