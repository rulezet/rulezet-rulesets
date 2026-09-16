rule TTP_XOR_QUAD_CurrentVersionRun_3296 {
  strings:
    $key_3296 = { 61 f9 [2] 45 f7 [2] 6e db [2] 40 f9 [2] 54 e2 [2] 5b f8 [2] 45 e5 [2] 47 e4 [2] 5c e2 [2] 40 e5 [2] 5c ca }

  condition:
    any of them
}