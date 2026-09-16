rule TTP_XOR_QUAD_CurrentVersionRun_2090 {
  strings:
    $key_2090 = { 73 ff [2] 57 f1 [2] 7c dd [2] 52 ff [2] 46 e4 [2] 49 fe [2] 57 e3 [2] 55 e2 [2] 4e e4 [2] 52 e3 [2] 4e cc }

  condition:
    any of them
}