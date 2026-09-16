rule TTP_XOR_QUAD_CurrentVersionRun_3890 {
  strings:
    $key_3890 = { 6b ff [2] 4f f1 [2] 64 dd [2] 4a ff [2] 5e e4 [2] 51 fe [2] 4f e3 [2] 4d e2 [2] 56 e4 [2] 4a e3 [2] 56 cc }

  condition:
    any of them
}