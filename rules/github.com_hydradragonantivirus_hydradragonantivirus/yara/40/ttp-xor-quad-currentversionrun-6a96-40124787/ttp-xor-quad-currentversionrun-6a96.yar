rule TTP_XOR_QUAD_CurrentVersionRun_6a96 {
  strings:
    $key_6a96 = { 39 f9 [2] 1d f7 [2] 36 db [2] 18 f9 [2] 0c e2 [2] 03 f8 [2] 1d e5 [2] 1f e4 [2] 04 e2 [2] 18 e5 [2] 04 ca }

  condition:
    any of them
}