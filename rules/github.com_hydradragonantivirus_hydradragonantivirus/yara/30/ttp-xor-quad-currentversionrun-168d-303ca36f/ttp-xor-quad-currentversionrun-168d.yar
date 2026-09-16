rule TTP_XOR_QUAD_CurrentVersionRun_168d {
  strings:
    $key_168d = { 45 e2 [2] 61 ec [2] 4a c0 [2] 64 e2 [2] 70 f9 [2] 7f e3 [2] 61 fe [2] 63 ff [2] 78 f9 [2] 64 fe [2] 78 d1 }

  condition:
    any of them
}