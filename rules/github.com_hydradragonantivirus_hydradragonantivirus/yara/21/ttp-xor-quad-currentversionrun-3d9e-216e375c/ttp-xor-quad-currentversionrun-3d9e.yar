rule TTP_XOR_QUAD_CurrentVersionRun_3d9e {
  strings:
    $key_3d9e = { 6e f1 [2] 4a ff [2] 61 d3 [2] 4f f1 [2] 5b ea [2] 54 f0 [2] 4a ed [2] 48 ec [2] 53 ea [2] 4f ed [2] 53 c2 }

  condition:
    any of them
}