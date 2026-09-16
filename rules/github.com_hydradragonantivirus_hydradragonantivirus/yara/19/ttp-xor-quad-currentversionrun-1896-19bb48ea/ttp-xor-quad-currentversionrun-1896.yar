rule TTP_XOR_QUAD_CurrentVersionRun_1896 {
  strings:
    $key_1896 = { 4b f9 [2] 6f f7 [2] 44 db [2] 6a f9 [2] 7e e2 [2] 71 f8 [2] 6f e5 [2] 6d e4 [2] 76 e2 [2] 6a e5 [2] 76 ca }

  condition:
    any of them
}