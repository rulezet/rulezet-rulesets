rule TTP_XOR_QUAD_CurrentVersionRun_7690 {
  strings:
    $key_7690 = { 25 ff [2] 01 f1 [2] 2a dd [2] 04 ff [2] 10 e4 [2] 1f fe [2] 01 e3 [2] 03 e2 [2] 18 e4 [2] 04 e3 [2] 18 cc }

  condition:
    any of them
}