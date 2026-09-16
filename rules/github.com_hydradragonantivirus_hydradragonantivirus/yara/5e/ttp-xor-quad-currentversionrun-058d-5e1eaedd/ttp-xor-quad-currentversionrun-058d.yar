rule TTP_XOR_QUAD_CurrentVersionRun_058d {
  strings:
    $key_058d = { 56 e2 [2] 72 ec [2] 59 c0 [2] 77 e2 [2] 63 f9 [2] 6c e3 [2] 72 fe [2] 70 ff [2] 6b f9 [2] 77 fe [2] 6b d1 }

  condition:
    any of them
}