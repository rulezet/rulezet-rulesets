rule TTP_XOR_QUAD_CurrentVersionRun_509e {
  strings:
    $key_509e = { 03 f1 [2] 27 ff [2] 0c d3 [2] 22 f1 [2] 36 ea [2] 39 f0 [2] 27 ed [2] 25 ec [2] 3e ea [2] 22 ed [2] 3e c2 }

  condition:
    any of them
}