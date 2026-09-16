rule TTP_XOR_QUAD_CurrentVersionRun_1291 {
  strings:
    $key_1291 = { 41 fe [2] 65 f0 [2] 4e dc [2] 60 fe [2] 74 e5 [2] 7b ff [2] 65 e2 [2] 67 e3 [2] 7c e5 [2] 60 e2 [2] 7c cd }

  condition:
    any of them
}