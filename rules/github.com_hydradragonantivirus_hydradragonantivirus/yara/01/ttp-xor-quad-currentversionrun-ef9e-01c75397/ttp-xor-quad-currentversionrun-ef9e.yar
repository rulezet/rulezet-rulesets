rule TTP_XOR_QUAD_CurrentVersionRun_ef9e {
  strings:
    $key_ef9e = { bc f1 [2] 98 ff [2] b3 d3 [2] 9d f1 [2] 89 ea [2] 86 f0 [2] 98 ed [2] 9a ec [2] 81 ea [2] 9d ed [2] 81 c2 }

  condition:
    any of them
}