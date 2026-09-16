rule TTP_XOR_QUAD_CurrentVersionRun_e091 {
  strings:
    $key_e091 = { b3 fe [2] 97 f0 [2] bc dc [2] 92 fe [2] 86 e5 [2] 89 ff [2] 97 e2 [2] 95 e3 [2] 8e e5 [2] 92 e2 [2] 8e cd }

  condition:
    any of them
}