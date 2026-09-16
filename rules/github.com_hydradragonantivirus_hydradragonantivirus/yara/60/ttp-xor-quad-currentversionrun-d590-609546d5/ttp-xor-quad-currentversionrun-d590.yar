rule TTP_XOR_QUAD_CurrentVersionRun_d590 {
  strings:
    $key_d590 = { 86 ff [2] a2 f1 [2] 89 dd [2] a7 ff [2] b3 e4 [2] bc fe [2] a2 e3 [2] a0 e2 [2] bb e4 [2] a7 e3 [2] bb cc }

  condition:
    any of them
}