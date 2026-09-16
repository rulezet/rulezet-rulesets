rule TTP_XOR_QUAD_CurrentVersionRun_a09f {
  strings:
    $key_a09f = { f3 f0 [2] d7 fe [2] fc d2 [2] d2 f0 [2] c6 eb [2] c9 f1 [2] d7 ec [2] d5 ed [2] ce eb [2] d2 ec [2] ce c3 }

  condition:
    any of them
}