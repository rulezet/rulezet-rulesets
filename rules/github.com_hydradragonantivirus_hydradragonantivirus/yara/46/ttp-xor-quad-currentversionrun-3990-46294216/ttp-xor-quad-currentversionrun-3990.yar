rule TTP_XOR_QUAD_CurrentVersionRun_3990 {
  strings:
    $key_3990 = { 6a ff [2] 4e f1 [2] 65 dd [2] 4b ff [2] 5f e4 [2] 50 fe [2] 4e e3 [2] 4c e2 [2] 57 e4 [2] 4b e3 [2] 57 cc }

  condition:
    any of them
}