rule TTP_XOR_QUAD_CurrentVersionRun_1696 {
  strings:
    $key_1696 = { 45 f9 [2] 61 f7 [2] 4a db [2] 64 f9 [2] 70 e2 [2] 7f f8 [2] 61 e5 [2] 63 e4 [2] 78 e2 [2] 64 e5 [2] 78 ca }

  condition:
    any of them
}