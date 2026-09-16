rule TTP_XOR_QUAD_CurrentVersionRun_dc90 {
  strings:
    $key_dc90 = { 8f ff [2] ab f1 [2] 80 dd [2] ae ff [2] ba e4 [2] b5 fe [2] ab e3 [2] a9 e2 [2] b2 e4 [2] ae e3 [2] b2 cc }

  condition:
    any of them
}