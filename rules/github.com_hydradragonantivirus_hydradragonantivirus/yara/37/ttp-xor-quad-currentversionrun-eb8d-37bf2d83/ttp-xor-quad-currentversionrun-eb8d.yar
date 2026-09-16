rule TTP_XOR_QUAD_CurrentVersionRun_eb8d {
  strings:
    $key_eb8d = { b8 e2 [2] 9c ec [2] b7 c0 [2] 99 e2 [2] 8d f9 [2] 82 e3 [2] 9c fe [2] 9e ff [2] 85 f9 [2] 99 fe [2] 85 d1 }

  condition:
    any of them
}