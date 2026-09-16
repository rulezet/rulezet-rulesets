rule TTP_XOR_QUAD_CurrentVersionRun_cf90 {
  strings:
    $key_cf90 = { 9c ff [2] b8 f1 [2] 93 dd [2] bd ff [2] a9 e4 [2] a6 fe [2] b8 e3 [2] ba e2 [2] a1 e4 [2] bd e3 [2] a1 cc }

  condition:
    any of them
}