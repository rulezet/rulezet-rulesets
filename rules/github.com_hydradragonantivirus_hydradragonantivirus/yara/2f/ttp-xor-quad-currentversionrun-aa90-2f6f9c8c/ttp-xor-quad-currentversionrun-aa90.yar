rule TTP_XOR_QUAD_CurrentVersionRun_aa90 {
  strings:
    $key_aa90 = { f9 ff [2] dd f1 [2] f6 dd [2] d8 ff [2] cc e4 [2] c3 fe [2] dd e3 [2] df e2 [2] c4 e4 [2] d8 e3 [2] c4 cc }

  condition:
    any of them
}