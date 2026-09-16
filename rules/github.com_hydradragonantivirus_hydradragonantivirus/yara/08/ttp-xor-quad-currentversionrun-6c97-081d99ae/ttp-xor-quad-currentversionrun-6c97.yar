rule TTP_XOR_QUAD_CurrentVersionRun_6c97 {
  strings:
    $key_6c97 = { 3f f8 [2] 1b f6 [2] 30 da [2] 1e f8 [2] 0a e3 [2] 05 f9 [2] 1b e4 [2] 19 e5 [2] 02 e3 [2] 1e e4 [2] 02 cb }

  condition:
    any of them
}