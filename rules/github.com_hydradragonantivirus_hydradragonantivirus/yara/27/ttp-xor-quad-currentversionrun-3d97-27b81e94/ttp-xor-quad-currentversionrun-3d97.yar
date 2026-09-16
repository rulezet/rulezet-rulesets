rule TTP_XOR_QUAD_CurrentVersionRun_3d97 {
  strings:
    $key_3d97 = { 6e f8 [2] 4a f6 [2] 61 da [2] 4f f8 [2] 5b e3 [2] 54 f9 [2] 4a e4 [2] 48 e5 [2] 53 e3 [2] 4f e4 [2] 53 cb }

  condition:
    any of them
}