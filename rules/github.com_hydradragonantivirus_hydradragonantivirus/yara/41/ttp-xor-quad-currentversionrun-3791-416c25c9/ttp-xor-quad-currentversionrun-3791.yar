rule TTP_XOR_QUAD_CurrentVersionRun_3791 {
  strings:
    $key_3791 = { 64 fe [2] 40 f0 [2] 6b dc [2] 45 fe [2] 51 e5 [2] 5e ff [2] 40 e2 [2] 42 e3 [2] 59 e5 [2] 45 e2 [2] 59 cd }

  condition:
    any of them
}