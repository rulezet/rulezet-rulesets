rule TTP_XOR_QUAD_CurrentVersionRun_7091 {
  strings:
    $key_7091 = { 23 fe [2] 07 f0 [2] 2c dc [2] 02 fe [2] 16 e5 [2] 19 ff [2] 07 e2 [2] 05 e3 [2] 1e e5 [2] 02 e2 [2] 1e cd }

  condition:
    any of them
}