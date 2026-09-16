rule TTP_XOR_QUAD_CurrentVersionRun_cc90 {
  strings:
    $key_cc90 = { 9f ff [2] bb f1 [2] 90 dd [2] be ff [2] aa e4 [2] a5 fe [2] bb e3 [2] b9 e2 [2] a2 e4 [2] be e3 [2] a2 cc }

  condition:
    any of them
}