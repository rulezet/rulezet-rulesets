rule TTP_XOR_QUAD_CurrentVersionRun_4b8d {
  strings:
    $key_4b8d = { 18 e2 [2] 3c ec [2] 17 c0 [2] 39 e2 [2] 2d f9 [2] 22 e3 [2] 3c fe [2] 3e ff [2] 25 f9 [2] 39 fe [2] 25 d1 }

  condition:
    any of them
}