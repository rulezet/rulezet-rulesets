rule TTP_XOR_QUAD_CurrentVersionRun_a08d {
  strings:
    $key_a08d = { f3 e2 [2] d7 ec [2] fc c0 [2] d2 e2 [2] c6 f9 [2] c9 e3 [2] d7 fe [2] d5 ff [2] ce f9 [2] d2 fe [2] ce d1 }

  condition:
    any of them
}