rule TTP_XOR_QUAD_CurrentVersionRun_f291 {
  strings:
    $key_f291 = { a1 fe [2] 85 f0 [2] ae dc [2] 80 fe [2] 94 e5 [2] 9b ff [2] 85 e2 [2] 87 e3 [2] 9c e5 [2] 80 e2 [2] 9c cd }

  condition:
    any of them
}