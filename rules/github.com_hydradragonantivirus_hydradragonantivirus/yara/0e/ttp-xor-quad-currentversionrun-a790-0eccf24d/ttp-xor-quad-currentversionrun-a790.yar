rule TTP_XOR_QUAD_CurrentVersionRun_a790 {
  strings:
    $key_a790 = { f4 ff [2] d0 f1 [2] fb dd [2] d5 ff [2] c1 e4 [2] ce fe [2] d0 e3 [2] d2 e2 [2] c9 e4 [2] d5 e3 [2] c9 cc }

  condition:
    any of them
}