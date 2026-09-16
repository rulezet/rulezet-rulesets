rule TTP_XOR_QUAD_CurrentVersionRun_578c {
  strings:
    $key_578c = { 04 e3 [2] 20 ed [2] 0b c1 [2] 25 e3 [2] 31 f8 [2] 3e e2 [2] 20 ff [2] 22 fe [2] 39 f8 [2] 25 ff [2] 39 d0 }

  condition:
    any of them
}