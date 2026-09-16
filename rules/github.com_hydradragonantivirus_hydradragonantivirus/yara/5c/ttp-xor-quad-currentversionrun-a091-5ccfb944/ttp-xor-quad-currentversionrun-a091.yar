rule TTP_XOR_QUAD_CurrentVersionRun_a091 {
  strings:
    $key_a091 = { f3 fe [2] d7 f0 [2] fc dc [2] d2 fe [2] c6 e5 [2] c9 ff [2] d7 e2 [2] d5 e3 [2] ce e5 [2] d2 e2 [2] ce cd }

  condition:
    any of them
}