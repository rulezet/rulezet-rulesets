rule TTP_XOR_QUAD_CurrentVersionRun_0296 {
  strings:
    $key_0296 = { 51 f9 [2] 75 f7 [2] 5e db [2] 70 f9 [2] 64 e2 [2] 6b f8 [2] 75 e5 [2] 77 e4 [2] 6c e2 [2] 70 e5 [2] 6c ca }

  condition:
    any of them
}