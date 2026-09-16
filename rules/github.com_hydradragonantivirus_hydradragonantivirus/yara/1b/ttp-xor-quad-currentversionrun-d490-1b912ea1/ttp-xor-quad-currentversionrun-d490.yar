rule TTP_XOR_QUAD_CurrentVersionRun_d490 {
  strings:
    $key_d490 = { 87 ff [2] a3 f1 [2] 88 dd [2] a6 ff [2] b2 e4 [2] bd fe [2] a3 e3 [2] a1 e2 [2] ba e4 [2] a6 e3 [2] ba cc }

  condition:
    any of them
}