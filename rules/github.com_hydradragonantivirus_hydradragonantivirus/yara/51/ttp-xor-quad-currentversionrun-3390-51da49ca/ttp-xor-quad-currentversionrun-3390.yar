rule TTP_XOR_QUAD_CurrentVersionRun_3390 {
  strings:
    $key_3390 = { 60 ff [2] 44 f1 [2] 6f dd [2] 41 ff [2] 55 e4 [2] 5a fe [2] 44 e3 [2] 46 e2 [2] 5d e4 [2] 41 e3 [2] 5d cc }

  condition:
    any of them
}