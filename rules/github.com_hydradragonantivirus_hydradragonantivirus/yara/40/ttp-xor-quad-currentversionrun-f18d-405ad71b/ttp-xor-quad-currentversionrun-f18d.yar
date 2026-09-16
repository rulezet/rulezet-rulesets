rule TTP_XOR_QUAD_CurrentVersionRun_f18d {
  strings:
    $key_f18d = { a2 e2 [2] 86 ec [2] ad c0 [2] 83 e2 [2] 97 f9 [2] 98 e3 [2] 86 fe [2] 84 ff [2] 9f f9 [2] 83 fe [2] 9f d1 }

  condition:
    any of them
}