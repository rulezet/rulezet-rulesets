rule TTP_XOR_QUAD_CurrentVersionRun_248d {
  strings:
    $key_248d = { 77 e2 [2] 53 ec [2] 78 c0 [2] 56 e2 [2] 42 f9 [2] 4d e3 [2] 53 fe [2] 51 ff [2] 4a f9 [2] 56 fe [2] 4a d1 }

  condition:
    any of them
}