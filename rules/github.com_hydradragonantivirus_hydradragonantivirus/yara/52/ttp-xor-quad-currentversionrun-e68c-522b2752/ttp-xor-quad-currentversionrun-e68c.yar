rule TTP_XOR_QUAD_CurrentVersionRun_e68c {
  strings:
    $key_e68c = { b5 e3 [2] 91 ed [2] ba c1 [2] 94 e3 [2] 80 f8 [2] 8f e2 [2] 91 ff [2] 93 fe [2] 88 f8 [2] 94 ff [2] 88 d0 }

  condition:
    any of them
}