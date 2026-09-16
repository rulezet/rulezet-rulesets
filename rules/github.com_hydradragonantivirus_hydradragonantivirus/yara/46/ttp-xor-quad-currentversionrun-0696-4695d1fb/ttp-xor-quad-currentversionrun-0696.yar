rule TTP_XOR_QUAD_CurrentVersionRun_0696 {
  strings:
    $key_0696 = { 55 f9 [2] 71 f7 [2] 5a db [2] 74 f9 [2] 60 e2 [2] 6f f8 [2] 71 e5 [2] 73 e4 [2] 68 e2 [2] 74 e5 [2] 68 ca }

  condition:
    any of them
}