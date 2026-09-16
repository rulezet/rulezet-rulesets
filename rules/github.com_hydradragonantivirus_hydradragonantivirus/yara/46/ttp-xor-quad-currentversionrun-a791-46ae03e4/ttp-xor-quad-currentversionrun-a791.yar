rule TTP_XOR_QUAD_CurrentVersionRun_a791 {
  strings:
    $key_a791 = { f4 fe [2] d0 f0 [2] fb dc [2] d5 fe [2] c1 e5 [2] ce ff [2] d0 e2 [2] d2 e3 [2] c9 e5 [2] d5 e2 [2] c9 cd }

  condition:
    any of them
}