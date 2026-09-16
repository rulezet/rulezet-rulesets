rule TTP_XOR_QUAD_CurrentVersionRun_4791 {
  strings:
    $key_4791 = { 14 fe [2] 30 f0 [2] 1b dc [2] 35 fe [2] 21 e5 [2] 2e ff [2] 30 e2 [2] 32 e3 [2] 29 e5 [2] 35 e2 [2] 29 cd }

  condition:
    any of them
}