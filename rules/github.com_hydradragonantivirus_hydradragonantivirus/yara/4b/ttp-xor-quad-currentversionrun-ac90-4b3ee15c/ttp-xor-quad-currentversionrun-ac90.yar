rule TTP_XOR_QUAD_CurrentVersionRun_ac90 {
  strings:
    $key_ac90 = { ff ff [2] db f1 [2] f0 dd [2] de ff [2] ca e4 [2] c5 fe [2] db e3 [2] d9 e2 [2] c2 e4 [2] de e3 [2] c2 cc }

  condition:
    any of them
}