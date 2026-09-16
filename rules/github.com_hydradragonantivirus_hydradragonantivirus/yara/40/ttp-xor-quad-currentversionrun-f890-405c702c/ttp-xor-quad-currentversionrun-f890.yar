rule TTP_XOR_QUAD_CurrentVersionRun_f890 {
  strings:
    $key_f890 = { ab ff [2] 8f f1 [2] a4 dd [2] 8a ff [2] 9e e4 [2] 91 fe [2] 8f e3 [2] 8d e2 [2] 96 e4 [2] 8a e3 [2] 96 cc }

  condition:
    any of them
}