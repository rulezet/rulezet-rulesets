rule TTP_XOR_QUAD_CurrentVersionRun_a78c {
  strings:
    $key_a78c = { f4 e3 [2] d0 ed [2] fb c1 [2] d5 e3 [2] c1 f8 [2] ce e2 [2] d0 ff [2] d2 fe [2] c9 f8 [2] d5 ff [2] c9 d0 }

  condition:
    any of them
}