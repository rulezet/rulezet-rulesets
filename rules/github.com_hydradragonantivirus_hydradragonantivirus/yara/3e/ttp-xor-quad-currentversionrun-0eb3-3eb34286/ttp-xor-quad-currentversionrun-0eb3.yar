rule TTP_XOR_QUAD_CurrentVersionRun_0eb3 {
  strings:
    $key_0eb3 = { 5d dc [2] 79 d2 [2] 52 fe [2] 7c dc [2] 68 c7 [2] 67 dd [2] 79 c0 [2] 7b c1 [2] 60 c7 [2] 7c c0 [2] 60 ef }

  condition:
    any of them
}