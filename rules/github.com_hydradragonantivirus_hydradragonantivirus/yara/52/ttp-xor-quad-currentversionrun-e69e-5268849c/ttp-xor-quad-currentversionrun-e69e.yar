rule TTP_XOR_QUAD_CurrentVersionRun_e69e {
  strings:
    $key_e69e = { b5 f1 [2] 91 ff [2] ba d3 [2] 94 f1 [2] 80 ea [2] 8f f0 [2] 91 ed [2] 93 ec [2] 88 ea [2] 94 ed [2] 88 c2 }

  condition:
    any of them
}