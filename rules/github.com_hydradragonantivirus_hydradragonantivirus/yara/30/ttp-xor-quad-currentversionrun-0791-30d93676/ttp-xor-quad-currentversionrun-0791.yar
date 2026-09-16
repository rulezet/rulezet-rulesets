rule TTP_XOR_QUAD_CurrentVersionRun_0791 {
  strings:
    $key_0791 = { 54 fe [2] 70 f0 [2] 5b dc [2] 75 fe [2] 61 e5 [2] 6e ff [2] 70 e2 [2] 72 e3 [2] 69 e5 [2] 75 e2 [2] 69 cd }

  condition:
    any of them
}