rule TTP_XOR_QUAD_CurrentVersionRun_cd8e {
  strings:
    $key_cd8e = { 9e e1 [2] ba ef [2] 91 c3 [2] bf e1 [2] ab fa [2] a4 e0 [2] ba fd [2] b8 fc [2] a3 fa [2] bf fd [2] a3 d2 }

  condition:
    any of them
}