rule TTP_XOR_QUAD_CurrentVersionRun_658d {
  strings:
    $key_658d = { 36 e2 [2] 12 ec [2] 39 c0 [2] 17 e2 [2] 03 f9 [2] 0c e3 [2] 12 fe [2] 10 ff [2] 0b f9 [2] 17 fe [2] 0b d1 }

  condition:
    any of them
}