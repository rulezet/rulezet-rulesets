rule TTP_XOR_QUAD_CurrentVersionRun_b091 {
  strings:
    $key_b091 = { e3 fe [2] c7 f0 [2] ec dc [2] c2 fe [2] d6 e5 [2] d9 ff [2] c7 e2 [2] c5 e3 [2] de e5 [2] c2 e2 [2] de cd }

  condition:
    any of them
}