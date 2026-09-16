rule TTP_XOR_QUAD_CurrentVersionRun_2390 {
  strings:
    $key_2390 = { 70 ff [2] 54 f1 [2] 7f dd [2] 51 ff [2] 45 e4 [2] 4a fe [2] 54 e3 [2] 56 e2 [2] 4d e4 [2] 51 e3 [2] 4d cc }

  condition:
    any of them
}