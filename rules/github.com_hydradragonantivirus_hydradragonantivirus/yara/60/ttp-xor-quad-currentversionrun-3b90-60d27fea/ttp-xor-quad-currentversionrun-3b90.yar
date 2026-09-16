rule TTP_XOR_QUAD_CurrentVersionRun_3b90 {
  strings:
    $key_3b90 = { 68 ff [2] 4c f1 [2] 67 dd [2] 49 ff [2] 5d e4 [2] 52 fe [2] 4c e3 [2] 4e e2 [2] 55 e4 [2] 49 e3 [2] 55 cc }

  condition:
    any of them
}