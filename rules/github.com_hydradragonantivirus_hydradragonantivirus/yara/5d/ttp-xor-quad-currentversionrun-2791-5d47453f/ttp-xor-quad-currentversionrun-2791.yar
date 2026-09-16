rule TTP_XOR_QUAD_CurrentVersionRun_2791 {
  strings:
    $key_2791 = { 74 fe [2] 50 f0 [2] 7b dc [2] 55 fe [2] 41 e5 [2] 4e ff [2] 50 e2 [2] 52 e3 [2] 49 e5 [2] 55 e2 [2] 49 cd }

  condition:
    any of them
}