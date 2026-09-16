rule TTP_XOR_QUAD_CurrentVersionRun_b49f {
  strings:
    $key_b49f = { e7 f0 [2] c3 fe [2] e8 d2 [2] c6 f0 [2] d2 eb [2] dd f1 [2] c3 ec [2] c1 ed [2] da eb [2] c6 ec [2] da c3 }

  condition:
    any of them
}