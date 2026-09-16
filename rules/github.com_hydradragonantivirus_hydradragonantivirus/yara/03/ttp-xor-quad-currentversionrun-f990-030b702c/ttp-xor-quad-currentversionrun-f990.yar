rule TTP_XOR_QUAD_CurrentVersionRun_f990 {
  strings:
    $key_f990 = { aa ff [2] 8e f1 [2] a5 dd [2] 8b ff [2] 9f e4 [2] 90 fe [2] 8e e3 [2] 8c e2 [2] 97 e4 [2] 8b e3 [2] 97 cc }

  condition:
    any of them
}