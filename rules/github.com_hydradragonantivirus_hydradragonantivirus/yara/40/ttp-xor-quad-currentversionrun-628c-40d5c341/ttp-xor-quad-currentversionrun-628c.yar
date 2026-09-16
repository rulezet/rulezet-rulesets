rule TTP_XOR_QUAD_CurrentVersionRun_628c {
  strings:
    $key_628c = { 31 e3 [2] 15 ed [2] 3e c1 [2] 10 e3 [2] 04 f8 [2] 0b e2 [2] 15 ff [2] 17 fe [2] 0c f8 [2] 10 ff [2] 0c d0 }

  condition:
    any of them
}