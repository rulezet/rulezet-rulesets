rule TTP_XOR_QUAD_CurrentVersionRun_e890 {
  strings:
    $key_e890 = { bb ff [2] 9f f1 [2] b4 dd [2] 9a ff [2] 8e e4 [2] 81 fe [2] 9f e3 [2] 9d e2 [2] 86 e4 [2] 9a e3 [2] 86 cc }

  condition:
    any of them
}