rule TTP_XOR_QUAD_CurrentVersionRun_609e {
  strings:
    $key_609e = { 33 f1 [2] 17 ff [2] 3c d3 [2] 12 f1 [2] 06 ea [2] 09 f0 [2] 17 ed [2] 15 ec [2] 0e ea [2] 12 ed [2] 0e c2 }

  condition:
    any of them
}