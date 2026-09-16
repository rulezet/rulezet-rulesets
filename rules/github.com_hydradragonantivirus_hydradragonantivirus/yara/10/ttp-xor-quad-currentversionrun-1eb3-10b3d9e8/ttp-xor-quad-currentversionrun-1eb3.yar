rule TTP_XOR_QUAD_CurrentVersionRun_1eb3 {
  strings:
    $key_1eb3 = { 4d dc [2] 69 d2 [2] 42 fe [2] 6c dc [2] 78 c7 [2] 77 dd [2] 69 c0 [2] 6b c1 [2] 70 c7 [2] 6c c0 [2] 70 ef }

  condition:
    any of them
}