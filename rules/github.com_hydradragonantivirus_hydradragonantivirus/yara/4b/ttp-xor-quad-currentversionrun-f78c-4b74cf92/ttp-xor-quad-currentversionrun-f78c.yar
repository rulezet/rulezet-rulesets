rule TTP_XOR_QUAD_CurrentVersionRun_f78c {
  strings:
    $key_f78c = { a4 e3 [2] 80 ed [2] ab c1 [2] 85 e3 [2] 91 f8 [2] 9e e2 [2] 80 ff [2] 82 fe [2] 99 f8 [2] 85 ff [2] 99 d0 }

  condition:
    any of them
}