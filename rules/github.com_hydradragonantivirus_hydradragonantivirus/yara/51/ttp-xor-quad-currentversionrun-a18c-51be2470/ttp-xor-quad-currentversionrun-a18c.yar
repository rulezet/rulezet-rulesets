rule TTP_XOR_QUAD_CurrentVersionRun_a18c {
  strings:
    $key_a18c = { f2 e3 [2] d6 ed [2] fd c1 [2] d3 e3 [2] c7 f8 [2] c8 e2 [2] d6 ff [2] d4 fe [2] cf f8 [2] d3 ff [2] cf d0 }

  condition:
    any of them
}