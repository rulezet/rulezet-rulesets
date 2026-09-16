rule TTP_XOR_QUAD_CurrentVersionRun_7890 {
  strings:
    $key_7890 = { 2b ff [2] 0f f1 [2] 24 dd [2] 0a ff [2] 1e e4 [2] 11 fe [2] 0f e3 [2] 0d e2 [2] 16 e4 [2] 0a e3 [2] 16 cc }

  condition:
    any of them
}