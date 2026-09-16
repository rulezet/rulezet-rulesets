rule TTP_XOR_QUAD_CurrentVersionRun_7390 {
  strings:
    $key_7390 = { 20 ff [2] 04 f1 [2] 2f dd [2] 01 ff [2] 15 e4 [2] 1a fe [2] 04 e3 [2] 06 e2 [2] 1d e4 [2] 01 e3 [2] 1d cc }

  condition:
    any of them
}