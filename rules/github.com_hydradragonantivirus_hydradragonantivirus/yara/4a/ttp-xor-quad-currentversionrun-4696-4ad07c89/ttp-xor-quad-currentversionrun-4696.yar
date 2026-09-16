rule TTP_XOR_QUAD_CurrentVersionRun_4696 {
  strings:
    $key_4696 = { 15 f9 [2] 31 f7 [2] 1a db [2] 34 f9 [2] 20 e2 [2] 2f f8 [2] 31 e5 [2] 33 e4 [2] 28 e2 [2] 34 e5 [2] 28 ca }

  condition:
    any of them
}