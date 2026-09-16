rule TTP_XOR_QUAD_CurrentVersionRun_6990 {
  strings:
    $key_6990 = { 3a ff [2] 1e f1 [2] 35 dd [2] 1b ff [2] 0f e4 [2] 00 fe [2] 1e e3 [2] 1c e2 [2] 07 e4 [2] 1b e3 [2] 07 cc }

  condition:
    any of them
}