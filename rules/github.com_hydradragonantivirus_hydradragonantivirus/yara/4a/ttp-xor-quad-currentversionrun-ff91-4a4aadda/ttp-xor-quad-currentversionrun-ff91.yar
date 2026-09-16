rule TTP_XOR_QUAD_CurrentVersionRun_ff91 {
  strings:
    $key_ff91 = { ac fe [2] 88 f0 [2] a3 dc [2] 8d fe [2] 99 e5 [2] 96 ff [2] 88 e2 [2] 8a e3 [2] 91 e5 [2] 8d e2 [2] 91 cd }

  condition:
    any of them
}