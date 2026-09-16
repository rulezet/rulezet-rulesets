rule TTP_XOR_QUAD_CurrentVersionRun_279e {
  strings:
    $key_279e = { 74 f1 [2] 50 ff [2] 7b d3 [2] 55 f1 [2] 41 ea [2] 4e f0 [2] 50 ed [2] 52 ec [2] 49 ea [2] 55 ed [2] 49 c2 }

  condition:
    any of them
}