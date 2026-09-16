rule TTP_XOR_QUAD_CurrentVersionRun_f790 {
  strings:
    $key_f790 = { a4 ff [2] 80 f1 [2] ab dd [2] 85 ff [2] 91 e4 [2] 9e fe [2] 80 e3 [2] 82 e2 [2] 99 e4 [2] 85 e3 [2] 99 cc }

  condition:
    any of them
}