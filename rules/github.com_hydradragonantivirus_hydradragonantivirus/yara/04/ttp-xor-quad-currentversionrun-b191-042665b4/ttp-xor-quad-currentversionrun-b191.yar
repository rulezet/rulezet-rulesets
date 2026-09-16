rule TTP_XOR_QUAD_CurrentVersionRun_b191 {
  strings:
    $key_b191 = { e2 fe [2] c6 f0 [2] ed dc [2] c3 fe [2] d7 e5 [2] d8 ff [2] c6 e2 [2] c4 e3 [2] df e5 [2] c3 e2 [2] df cd }

  condition:
    any of them
}