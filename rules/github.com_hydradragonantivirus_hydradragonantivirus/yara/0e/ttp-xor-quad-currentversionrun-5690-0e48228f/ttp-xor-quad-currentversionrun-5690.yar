rule TTP_XOR_QUAD_CurrentVersionRun_5690 {
  strings:
    $key_5690 = { 05 ff [2] 21 f1 [2] 0a dd [2] 24 ff [2] 30 e4 [2] 3f fe [2] 21 e3 [2] 23 e2 [2] 38 e4 [2] 24 e3 [2] 38 cc }

  condition:
    any of them
}