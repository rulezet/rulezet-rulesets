rule TTP_XOR_QUAD_CurrentVersionRun_a183 {
  strings:
    $key_a183 = { f2 ec [2] d6 e2 [2] fd ce [2] d3 ec [2] c7 f7 [2] c8 ed [2] d6 f0 [2] d4 f1 [2] cf f7 [2] d3 f0 [2] cf df }

  condition:
    any of them
}