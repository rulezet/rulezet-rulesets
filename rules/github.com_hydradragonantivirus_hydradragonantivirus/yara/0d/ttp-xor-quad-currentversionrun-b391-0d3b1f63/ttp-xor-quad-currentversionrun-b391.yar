rule TTP_XOR_QUAD_CurrentVersionRun_b391 {
  strings:
    $key_b391 = { e0 fe [2] c4 f0 [2] ef dc [2] c1 fe [2] d5 e5 [2] da ff [2] c4 e2 [2] c6 e3 [2] dd e5 [2] c1 e2 [2] dd cd }

  condition:
    any of them
}