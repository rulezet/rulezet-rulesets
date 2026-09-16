rule TTP_XOR_QUAD_CurrentVersionRun_7790 {
  strings:
    $key_7790 = { 24 ff [2] 00 f1 [2] 2b dd [2] 05 ff [2] 11 e4 [2] 1e fe [2] 00 e3 [2] 02 e2 [2] 19 e4 [2] 05 e3 [2] 19 cc }

  condition:
    any of them
}