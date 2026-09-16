rule TTP_XOR_QUAD_CurrentVersionRun_e690 {
  strings:
    $key_e690 = { b5 ff [2] 91 f1 [2] ba dd [2] 94 ff [2] 80 e4 [2] 8f fe [2] 91 e3 [2] 93 e2 [2] 88 e4 [2] 94 e3 [2] 88 cc }

  condition:
    any of them
}