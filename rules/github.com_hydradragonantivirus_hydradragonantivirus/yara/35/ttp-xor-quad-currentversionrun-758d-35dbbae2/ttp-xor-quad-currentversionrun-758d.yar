rule TTP_XOR_QUAD_CurrentVersionRun_758d {
  strings:
    $key_758d = { 26 e2 [2] 02 ec [2] 29 c0 [2] 07 e2 [2] 13 f9 [2] 1c e3 [2] 02 fe [2] 00 ff [2] 1b f9 [2] 07 fe [2] 1b d1 }

  condition:
    any of them
}