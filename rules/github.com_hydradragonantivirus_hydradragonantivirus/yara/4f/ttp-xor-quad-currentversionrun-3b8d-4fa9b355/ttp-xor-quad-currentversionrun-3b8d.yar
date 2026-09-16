rule TTP_XOR_QUAD_CurrentVersionRun_3b8d {
  strings:
    $key_3b8d = { 68 e2 [2] 4c ec [2] 67 c0 [2] 49 e2 [2] 5d f9 [2] 52 e3 [2] 4c fe [2] 4e ff [2] 55 f9 [2] 49 fe [2] 55 d1 }

  condition:
    any of them
}