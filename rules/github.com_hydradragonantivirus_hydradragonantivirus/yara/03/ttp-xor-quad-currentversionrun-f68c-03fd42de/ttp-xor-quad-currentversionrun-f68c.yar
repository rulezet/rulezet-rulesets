rule TTP_XOR_QUAD_CurrentVersionRun_f68c {
  strings:
    $key_f68c = { a5 e3 [2] 81 ed [2] aa c1 [2] 84 e3 [2] 90 f8 [2] 9f e2 [2] 81 ff [2] 83 fe [2] 98 f8 [2] 84 ff [2] 98 d0 }

  condition:
    any of them
}