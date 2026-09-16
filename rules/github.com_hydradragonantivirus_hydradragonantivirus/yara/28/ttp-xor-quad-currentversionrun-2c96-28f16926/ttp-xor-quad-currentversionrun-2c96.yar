rule TTP_XOR_QUAD_CurrentVersionRun_2c96 {
  strings:
    $key_2c96 = { 7f f9 [2] 5b f7 [2] 70 db [2] 5e f9 [2] 4a e2 [2] 45 f8 [2] 5b e5 [2] 59 e4 [2] 42 e2 [2] 5e e5 [2] 42 ca }

  condition:
    any of them
}