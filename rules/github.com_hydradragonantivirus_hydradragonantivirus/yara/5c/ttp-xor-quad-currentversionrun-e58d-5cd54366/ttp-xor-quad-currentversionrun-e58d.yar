rule TTP_XOR_QUAD_CurrentVersionRun_e58d {
  strings:
    $key_e58d = { b6 e2 [2] 92 ec [2] b9 c0 [2] 97 e2 [2] 83 f9 [2] 8c e3 [2] 92 fe [2] 90 ff [2] 8b f9 [2] 97 fe [2] 8b d1 }

  condition:
    any of them
}