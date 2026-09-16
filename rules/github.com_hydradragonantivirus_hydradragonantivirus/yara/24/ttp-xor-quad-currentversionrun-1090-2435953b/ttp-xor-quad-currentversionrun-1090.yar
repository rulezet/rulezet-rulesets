rule TTP_XOR_QUAD_CurrentVersionRun_1090 {
  strings:
    $key_1090 = { 43 ff [2] 67 f1 [2] 4c dd [2] 62 ff [2] 76 e4 [2] 79 fe [2] 67 e3 [2] 65 e2 [2] 7e e4 [2] 62 e3 [2] 7e cc }

  condition:
    any of them
}