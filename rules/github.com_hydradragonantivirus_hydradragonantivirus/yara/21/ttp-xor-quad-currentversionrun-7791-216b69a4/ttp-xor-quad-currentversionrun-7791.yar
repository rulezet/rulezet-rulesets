rule TTP_XOR_QUAD_CurrentVersionRun_7791 {
  strings:
    $key_7791 = { 24 fe [2] 00 f0 [2] 2b dc [2] 05 fe [2] 11 e5 [2] 1e ff [2] 00 e2 [2] 02 e3 [2] 19 e5 [2] 05 e2 [2] 19 cd }

  condition:
    any of them
}