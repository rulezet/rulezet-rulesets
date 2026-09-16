rule TTP_XOR_QUAD_CurrentVersionRun_f58d {
  strings:
    $key_f58d = { a6 e2 [2] 82 ec [2] a9 c0 [2] 87 e2 [2] 93 f9 [2] 9c e3 [2] 82 fe [2] 80 ff [2] 9b f9 [2] 87 fe [2] 9b d1 }

  condition:
    any of them
}