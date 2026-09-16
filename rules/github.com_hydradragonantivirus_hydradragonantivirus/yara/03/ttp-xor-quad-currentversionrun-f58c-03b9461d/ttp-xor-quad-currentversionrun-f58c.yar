rule TTP_XOR_QUAD_CurrentVersionRun_f58c {
  strings:
    $key_f58c = { a6 e3 [2] 82 ed [2] a9 c1 [2] 87 e3 [2] 93 f8 [2] 9c e2 [2] 82 ff [2] 80 fe [2] 9b f8 [2] 87 ff [2] 9b d0 }

  condition:
    any of them
}