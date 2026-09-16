rule TTP_XOR_QUAD_CurrentVersionRun_f48d {
  strings:
    $key_f48d = { a7 e2 [2] 83 ec [2] a8 c0 [2] 86 e2 [2] 92 f9 [2] 9d e3 [2] 83 fe [2] 81 ff [2] 9a f9 [2] 86 fe [2] 9a d1 }

  condition:
    any of them
}