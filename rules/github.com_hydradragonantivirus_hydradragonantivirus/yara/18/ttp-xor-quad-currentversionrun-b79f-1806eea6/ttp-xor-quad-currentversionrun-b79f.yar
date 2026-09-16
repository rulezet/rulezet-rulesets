rule TTP_XOR_QUAD_CurrentVersionRun_b79f {
  strings:
    $key_b79f = { e4 f0 [2] c0 fe [2] eb d2 [2] c5 f0 [2] d1 eb [2] de f1 [2] c0 ec [2] c2 ed [2] d9 eb [2] c5 ec [2] d9 c3 }

  condition:
    any of them
}