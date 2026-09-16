rule TTP_XOR_QUAD_CurrentVersionRun_ea90 {
  strings:
    $key_ea90 = { b9 ff [2] 9d f1 [2] b6 dd [2] 98 ff [2] 8c e4 [2] 83 fe [2] 9d e3 [2] 9f e2 [2] 84 e4 [2] 98 e3 [2] 84 cc }

  condition:
    any of them
}