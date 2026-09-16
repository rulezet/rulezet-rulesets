rule TTP_XOR_QUAD_CurrentVersionRun_b690 {
  strings:
    $key_b690 = { e5 ff [2] c1 f1 [2] ea dd [2] c4 ff [2] d0 e4 [2] df fe [2] c1 e3 [2] c3 e2 [2] d8 e4 [2] c4 e3 [2] d8 cc }

  condition:
    any of them
}