rule TTP_XOR_QUAD_CurrentVersionRun_268d {
  strings:
    $key_268d = { 75 e2 [2] 51 ec [2] 7a c0 [2] 54 e2 [2] 40 f9 [2] 4f e3 [2] 51 fe [2] 53 ff [2] 48 f9 [2] 54 fe [2] 48 d1 }

  condition:
    any of them
}