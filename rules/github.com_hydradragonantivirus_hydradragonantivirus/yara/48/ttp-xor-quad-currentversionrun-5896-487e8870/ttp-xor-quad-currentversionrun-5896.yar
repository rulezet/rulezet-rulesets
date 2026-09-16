rule TTP_XOR_QUAD_CurrentVersionRun_5896 {
  strings:
    $key_5896 = { 0b f9 [2] 2f f7 [2] 04 db [2] 2a f9 [2] 3e e2 [2] 31 f8 [2] 2f e5 [2] 2d e4 [2] 36 e2 [2] 2a e5 [2] 36 ca }

  condition:
    any of them
}