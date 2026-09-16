rule TTP_XOR_QUAD_CurrentVersionRun_dd90 {
  strings:
    $key_dd90 = { 8e ff [2] aa f1 [2] 81 dd [2] af ff [2] bb e4 [2] b4 fe [2] aa e3 [2] a8 e2 [2] b3 e4 [2] af e3 [2] b3 cc }

  condition:
    any of them
}