rule TTP_XOR_QUAD_CurrentVersionRun_248c {
  strings:
    $key_248c = { 77 e3 [2] 53 ed [2] 78 c1 [2] 56 e3 [2] 42 f8 [2] 4d e2 [2] 53 ff [2] 51 fe [2] 4a f8 [2] 56 ff [2] 4a d0 }

  condition:
    any of them
}