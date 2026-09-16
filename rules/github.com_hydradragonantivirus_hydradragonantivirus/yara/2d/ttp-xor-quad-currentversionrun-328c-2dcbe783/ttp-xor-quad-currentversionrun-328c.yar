rule TTP_XOR_QUAD_CurrentVersionRun_328c {
  strings:
    $key_328c = { 61 e3 [2] 45 ed [2] 6e c1 [2] 40 e3 [2] 54 f8 [2] 5b e2 [2] 45 ff [2] 47 fe [2] 5c f8 [2] 40 ff [2] 5c d0 }

  condition:
    any of them
}