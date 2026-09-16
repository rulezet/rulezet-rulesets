rule TTP_XOR_QUAD_CurrentVersionRun_4790 {
  strings:
    $key_4790 = { 14 ff [2] 30 f1 [2] 1b dd [2] 35 ff [2] 21 e4 [2] 2e fe [2] 30 e3 [2] 32 e2 [2] 29 e4 [2] 35 e3 [2] 29 cc }

  condition:
    any of them
}