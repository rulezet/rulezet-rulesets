rule TTP_XOR_QUAD_CurrentVersionRun_bb90 {
  strings:
    $key_bb90 = { e8 ff [2] cc f1 [2] e7 dd [2] c9 ff [2] dd e4 [2] d2 fe [2] cc e3 [2] ce e2 [2] d5 e4 [2] c9 e3 [2] d5 cc }

  condition:
    any of them
}