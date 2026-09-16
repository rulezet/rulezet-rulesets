rule TTP_XOR_QUAD_CurrentVersionRun_7090 {
  strings:
    $key_7090 = { 23 ff [2] 07 f1 [2] 2c dd [2] 02 ff [2] 16 e4 [2] 19 fe [2] 07 e3 [2] 05 e2 [2] 1e e4 [2] 02 e3 [2] 1e cc }

  condition:
    any of them
}