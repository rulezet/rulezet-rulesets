rule TTP_XOR_QUAD_CurrentVersionRun_c490 {
  strings:
    $key_c490 = { 97 ff [2] b3 f1 [2] 98 dd [2] b6 ff [2] a2 e4 [2] ad fe [2] b3 e3 [2] b1 e2 [2] aa e4 [2] b6 e3 [2] aa cc }

  condition:
    any of them
}