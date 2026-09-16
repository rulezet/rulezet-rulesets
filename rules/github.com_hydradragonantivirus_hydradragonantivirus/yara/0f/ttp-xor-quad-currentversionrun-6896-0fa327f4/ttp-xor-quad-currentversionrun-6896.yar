rule TTP_XOR_QUAD_CurrentVersionRun_6896 {
  strings:
    $key_6896 = { 3b f9 [2] 1f f7 [2] 34 db [2] 1a f9 [2] 0e e2 [2] 01 f8 [2] 1f e5 [2] 1d e4 [2] 06 e2 [2] 1a e5 [2] 06 ca }

  condition:
    any of them
}