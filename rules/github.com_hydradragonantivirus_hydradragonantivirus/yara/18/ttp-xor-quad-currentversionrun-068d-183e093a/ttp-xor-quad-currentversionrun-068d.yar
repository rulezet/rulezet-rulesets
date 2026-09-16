rule TTP_XOR_QUAD_CurrentVersionRun_068d {
  strings:
    $key_068d = { 55 e2 [2] 71 ec [2] 5a c0 [2] 74 e2 [2] 60 f9 [2] 6f e3 [2] 71 fe [2] 73 ff [2] 68 f9 [2] 74 fe [2] 68 d1 }

  condition:
    any of them
}