rule TTP_XOR_QUAD_CurrentVersionRun_5890 {
  strings:
    $key_5890 = { 0b ff [2] 2f f1 [2] 04 dd [2] 2a ff [2] 3e e4 [2] 31 fe [2] 2f e3 [2] 2d e2 [2] 36 e4 [2] 2a e3 [2] 36 cc }

  condition:
    any of them
}