rule TTP_XOR_QUAD_CurrentVersionRun_1b8d {
  strings:
    $key_1b8d = { 48 e2 [2] 6c ec [2] 47 c0 [2] 69 e2 [2] 7d f9 [2] 72 e3 [2] 6c fe [2] 6e ff [2] 75 f9 [2] 69 fe [2] 75 d1 }

  condition:
    any of them
}